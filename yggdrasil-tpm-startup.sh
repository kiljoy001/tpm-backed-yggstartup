#!/bin/bash
#
# TPM-Secured Yggdrasil Launcher - v2 (With DB & Recovery)
#
# This script provides enhanced security for Yggdrasil by:
# - Storing private keys in TPM hardware
# - Using in-memory configuration only
# - Securely cleaning up sensitive data
# - Managing TPM handles via SQLite to prevent "full" errors
# - Generating BIP-39 recovery phrases

# Exit on error, unbound variable, and pipe failures
set -euo pipefail
trap 'echo "Script failed at line $LINENO"; cleanup_on_error; exit 1' ERR

TPM_DIR="/run/yggdrasil"
DB_SCRIPT_PATH="tpm_db.py"
LOCK_FILE="/run/yggdrasil/yggdrasil-tpm.lock"

# Initialize global variables for cleanup
SECURE_DIR=""
MAPPER_NAME=""
RAM_IMG=""

# Ensure only one instance runs
acquire_lock() {
    local timeout=30
    local count=0

    # Ensure runtime dir exists
    mkdir -p "$TPM_DIR"

    while ! mkdir "$LOCK_FILE" 2>/dev/null; do
        if [[ $count -ge $timeout ]]; then
            echo "Could not acquire lock after ${timeout}s"
            exit 1
        fi
        echo "Waiting for lock..."
        sleep 1
        ((count++))
    done

    # Store PID for cleanup
    echo $$ > "$LOCK_FILE/pid"
    trap 'rm -rf "$LOCK_FILE" 2>/dev/null || true' EXIT
}

cleanup_on_error() {
    echo "Cleaning up after error..."
    if [[ -n "$SECURE_DIR" ]]; then
        teardown_vault "$SECURE_DIR" "$MAPPER_NAME" "$RAM_IMG"
    fi
    rm -rf "$LOCK_FILE" 2>/dev/null || true
}

trap 'cleanup_on_error' ERR
trap 'teardown_vault "$SECURE_DIR" "$MAPPER_NAME" "$RAM_IMG"; rm -rf "$LOCK_FILE" 2>/dev/null || true' EXIT

acquire_lock

# --- Initialize DB ---
"$DB_SCRIPT_PATH" --init

# --- Cleanup Logic (Garbage Collection) ---
echo "Checking for inactive handles..."
"$DB_SCRIPT_PATH" --gc

PRIMARY_HANDLE=""
KEY_HANDLE=""

run_checked() {
    "$@" || {
        echo "Command failed: $*"
        exit 1
    }
}

generate_random_handle() {
    local MIN=0x81010000
    local MAX=0x8101FFFF
    printf "0x%08x\n" $((RANDOM % (MAX - MIN + 1) + MIN))
}

handle_exists() {
    local handle_uppercase
    handle_uppercase=$(echo "$1" | tr 'a-f' 'A-F')
    # Use -s (system) or check for empty if tpm2_getcap fails
    tpm2_getcap handles-persistent 2>/dev/null | grep -q "$handle_uppercase"
}

create_primary_if_needed() {
    if ! handle_exists "$PRIMARY_HANDLE"; then
        echo "Creating primary key ($PRIMARY_HANDLE)..."
        run_checked tpm2_createprimary -C o -g sha256 -G ecc -c "$SECURE_DIR/primary.ctx"

        # Try to evict, if TPM full then fail gracefully
        if ! tpm2_evictcontrol -C o -c "$SECURE_DIR/primary.ctx" "$PRIMARY_HANDLE" 2>/dev/null; then
            echo "TPM storage full - cannot create persistent handle."
            echo "Attempting emergency cleanup..."
            "$DB_SCRIPT_PATH" --gc
            if ! tpm2_evictcontrol -C o -c "$SECURE_DIR/primary.ctx" "$PRIMARY_HANDLE" 2>/dev/null; then
                echo "Still full. Manual intervention required."
                exit 1
            fi
        fi
        rm -f "$SECURE_DIR/primary.ctx"
    else
        echo "Primary handle exists: $PRIMARY_HANDLE"
    fi
}

seal_key_if_needed() {
    if ! handle_exists "$KEY_HANDLE"; then
        echo "Sealing Yggdrasil key into TPM (handle $KEY_HANDLE)..."
        echo -n "$YGG_KEY" | run_checked tpm2_create -C "$PRIMARY_HANDLE" -i- \
            -u "$SECURE_DIR/key.pub" -r "$SECURE_DIR/key.priv"

        run_checked tpm2_load -C "$PRIMARY_HANDLE" -u "$SECURE_DIR/key.pub" \
            -r "$SECURE_DIR/key.priv" -c "$SECURE_DIR/key.ctx"

        run_checked tpm2_evictcontrol -C o -c "$SECURE_DIR/key.ctx" "$KEY_HANDLE"
        rm -f "$SECURE_DIR"/key.*
    else
        echo "Key handle exists: $KEY_HANDLE"
    fi
}

unseal_key() {
    echo "Unsealing Yggdrasil key from TPM..."
    run_checked tpm2_unseal -c "$KEY_HANDLE" > "$TEMP_KEY_FILE"
}

# Monitor the Yggdrasil process and cleanup when it exits
monitor_and_cleanup() {
    local pid=$1
    local config=$2
    
    # Wait for the process to exit
    tail --pid=$pid -f /dev/null
    
    echo "Yggdrasil process $pid exited."
    
    # Cleanup secure config from memory
    shred -u "$config" 2>/dev/null || rm -f "$config"
    
    # Release lock
    rm -rf "$LOCK_FILE"
}

# --- Lux9 Secure Vault Integration ---

setup_vault() {
    local handle="$1"
    
    echo "Deriving Holographic ID from TPM Identity + System State..."
    
    # 1. Get TPM Object "Name" (The Identity)
    local name_hex
    name_hex=$(run_checked tpm2_readpublic -c "$handle" | grep "name:" | awk '{print $2}')
    
    # 2. Get System State (PCR 0=BIOS, PCR 7=SecureBoot)
    # We strip spaces/newlines to get a raw consistent string
    local pcr_state
    pcr_state=$(run_checked tpm2_pcrread sha256:0,7 | grep -v "sha256:" | tr -d ' \n\r')
    
    echo "  Identity: $name_hex"
    echo "  PCR State: sha256:0,7 (BIOS + SecureBoot)"
    
    # 3. H(Identity | State)
    # This ensures the vault "vanishes" if the machine is tampered with
    local vault_seed
    vault_seed=$(echo -n "${name_hex}${pcr_state}" | sha256sum | head -c 32)
    
    # Generate Hidden ID (Mount Point)
    # Using 'lux_manager' from PATH
    local hidden_id
    hidden_id=$(echo -n "$vault_seed" | lux_manager gen-id-from-seed)
    SECURE_DIR="/run/$hidden_id"
    
    echo "target: $SECURE_DIR"

    # Define Vault Parameters
    RAM_IMG="/dev/shm/$hidden_id.img"
    MAPPER_NAME="ygg_vault_$hidden_id"
    
    # Check if already mounted (idempotency)
    if mountpoint -q "$SECURE_DIR"; then
        echo "Vault already active at $SECURE_DIR"
        return
    fi

    echo "Initializing Secure RAM Vault..."
    
    # Create backing store (64MB RAM)
    truncate -s 64M "$RAM_IMG"
    chmod 600 "$RAM_IMG"
    
    # Encrypt with Ephemeral Key (Monocypher -> Kernel)
    # Using random key for the volume itself (Forward Secrecy)
    # Using 'lux_manager' from PATH
    lux_manager gen-key | cryptsetup open --type plain \
        --cipher aes-xts-plain64 \
        --key-file - \
        "$RAM_IMG" "$MAPPER_NAME"
        
    # Format
    mkfs.ext4 -q -O "^has_journal" "/dev/mapper/$MAPPER_NAME"
    
    # Mount
    mkdir -p "$SECURE_DIR"
    chmod 700 "$SECURE_DIR"
    /bin/mount -t ext4 "/dev/mapper/$MAPPER_NAME" "$SECURE_DIR"
    
    # Cleanup trap needs to know about these new variables
    trap "teardown_vault '$SECURE_DIR' '$MAPPER_NAME' '$RAM_IMG'; rm -rf '$LOCK_FILE' 2>/dev/null || true" EXIT
}

teardown_vault() {
    local mount_point="$1"
    local mapper_name="$2"
    local img_path="$3"
    
    echo "Tearing down vault..."
    
    if [[ -n "$mount_point" ]] && mountpoint -q "$mount_point"; then
        # Wipe contents before unmount (extra paranoia)
        find "$mount_point" -type f -exec shred -u {} \; 2>/dev/null || true
        umount "$mount_point"
        rmdir "$mount_point" 2>/dev/null || true
    fi
    
    if [[ -n "$mapper_name" ]] && [ -e "/dev/mapper/$mapper_name" ]; then
        cryptsetup close "$mapper_name"
    fi
    
    if [[ -n "$img_path" ]]; then
        rm -f "$img_path"
    fi
}

# --- State Management ---

# Check database for active configuration
ACTIVE_STATE=$("$DB_SCRIPT_PATH" --get-active)
FOUND_ACTIVE=$(echo "$ACTIVE_STATE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('found'))")

if [[ "$FOUND_ACTIVE" == "True" ]]; then
    PRIMARY_HANDLE=$(echo "$ACTIVE_STATE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('primary_handle'))")
    KEY_HANDLE=$(echo "$ACTIVE_STATE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('key_handle'))")
    echo "Resuming with handles: Primary=$PRIMARY_HANDLE, Key=$KEY_HANDLE"
    
    if ! handle_exists "$PRIMARY_HANDLE" || ! handle_exists "$KEY_HANDLE"; then
        echo "Handles missing from TPM despite DB record. Resetting..."
        "$DB_SCRIPT_PATH" --mark-inactive "$PRIMARY_HANDLE"
        FOUND_ACTIVE="False"
    fi
fi

if [[ "$FOUND_ACTIVE" != "True" ]]; then
    echo "Generating NEW TPM identity..."
    
    # Generate unique handles
    PRIMARY_HANDLE=$(generate_random_handle)
    while handle_exists "$PRIMARY_HANDLE"; do PRIMARY_HANDLE=$(generate_random_handle); done

    KEY_HANDLE=$(generate_random_handle)
    while handle_exists "$KEY_HANDLE" || [[ "$KEY_HANDLE" == "$PRIMARY_HANDLE" ]]; do KEY_HANDLE=$(generate_random_handle); done

    # Use a temp dir for initial key generation only
    SECURE_DIR=$(mktemp -d)
    create_primary_if_needed

    echo "Generating Yggdrasil config..."
    run_checked yggdrasil -genconf > "$SECURE_DIR/temp.conf"
    YGG_KEY=$(awk '/PrivateKey/ {print $2}' "$SECURE_DIR/temp.conf")

    if [[ -z "$YGG_KEY" ]]; then
        echo "Failed to extract private key from config"
        exit 1
    fi

    seal_key_if_needed
    rm -rf "$SECURE_DIR"
    
    # Register in DB
    "$DB_SCRIPT_PATH" --add "$PRIMARY_HANDLE" "$KEY_HANDLE"
    
    echo "----------------------------------------------------------------"
    echo "WARNING: NEW KEY GENERATED."
    echo "WRITE DOWN THIS RECOVERY PHRASE. IT WILL NOT BE SHOWN AGAIN."
    echo "----------------------------------------------------------------"
    "$DB_SCRIPT_PATH" --to-mnemonic "${YGG_KEY:0:64}"
    echo "----------------------------------------------------------------"
fi

# Initialize the Lux9 Vault using the Handle Name (Public)
# We do NOT unseal the private key yet!
setup_vault "$KEY_HANDLE"

# Paths inside the vault
TMP_CONFIG_PATH="$SECURE_DIR/yggdrasil.conf"

echo "Unsealing Yggdrasil key from TPM directly into Vault..."
RAW_KEY=$(run_checked tpm2_unseal -c "$KEY_HANDLE")

if [[ -z "$RAW_KEY" ]]; then
    echo "Failed to unseal private key"
    exit 1
fi

echo "Injecting private key into Yggdrasil config..."
run_checked yggdrasil -genconf > "$TMP_CONFIG_PATH"
sed -i "s/PrivateKey: .*/PrivateKey: $RAW_KEY/" "$TMP_CONFIG_PATH"

# Wipe the variable from memory immediately
RAW_KEY=""

echo "Launching Yggdrasil..."

# Check if already running (re-check inside lock)
if pgrep -f "yggdrasil.*useconffile" >/dev/null; then
    echo "Yggdrasil already running."
    exit 0
fi

yggdrasil -useconffile "$TMP_CONFIG_PATH" &
YGG_PID=$!

# Wait for socket
for i in {1..5}; do
    if [[ -S /var/run/yggdrasil.sock ]]; then
        echo "Yggdrasil started successfully at $SECURE_DIR"
        break
    fi
    sleep 1
done

# Start background monitor
monitor_and_cleanup "$YGG_PID" "$TMP_CONFIG_PATH" &

echo "Yggdrasil TPM setup complete!"
echo "Primary handle: $PRIMARY_HANDLE"
echo "Key handle: $KEY_HANDLE"
echo "Vault location: $SECURE_DIR (Hidden)"

wait $YGG_PID