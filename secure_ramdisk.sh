#!/bin/bash
set -euo pipefail

# Configuration
RAM_IMG="/dev/shm/secure_vault.img"
MAPPER_NAME="secure_ram_vault"
MOUNT_POINT="/run/secure_vault"
SIZE="64M" # Size of the vault

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

setup() {
    echo "[+] Creating RAM container (${SIZE})..."
    truncate -s "$SIZE" "$RAM_IMG"
    chmod 600 "$RAM_IMG"

    echo "[+] Finding loop device..."
    LOOP_DEV=$(losetup -f)

    echo "[+] Generating Lux9 Identity (Elligator)..."
    # Generate a random-looking directory name derived from an Elligator key
    # This acts as a "Hidden ID" for the volume
    HIDDEN_ID=$(./lux_manager gen-id)
    MOUNT_POINT="/run/$HIDDEN_ID"
    
    echo "[+] Encrypting RAM container (Monocypher Key -> DM-Crypt)..."
    # Use Monocypher (ChaCha20) to generate the volume key
    ./lux_manager gen-key | cryptsetup open --type plain \
        --cipher chacha20-random \
        --key-file - \
        "$RAM_IMG" "$MAPPER_NAME"

    echo "[+] Formatting (ext4)..."
    mkfs.ext4 -q -O "^has_journal" "/dev/mapper/$MAPPER_NAME"

    echo "[+] Mounting to $MOUNT_POINT..."
    mkdir -p "$MOUNT_POINT"
    chmod 700 "$MOUNT_POINT"
    mount -t ext4 "/dev/mapper/$MAPPER_NAME" "$MOUNT_POINT"

    echo "✅ Secure RAM Vault active at: $MOUNT_POINT"
    echo "   Key Source: Monocypher (ChaCha20-DJB)"
    echo "   Identity:   Elligator Encoded (Steganographic)"
}

teardown() {
    echo "[-] Tearing down Secure RAM Vault..."
    
    # Find where the mapper device is mounted
    MOUNT_POINT=$(findmnt -n -o TARGET -S "/dev/mapper/$MAPPER_NAME" || echo "")

    # 1. Unmount
    if [[ -n "$MOUNT_POINT" ]]; then
        echo "    Unmounting $MOUNT_POINT..."
        umount "$MOUNT_POINT"
        rmdir "$MOUNT_POINT" 2>/dev/null || true
    else
        echo "    Not mounted."
    fi

    # 2. Close encryption (Wipes key from kernel memory)
    if [ -e "/dev/mapper/$MAPPER_NAME" ]; then
        cryptsetup close "$MAPPER_NAME"
    fi

    # 3. Remove RAM file
    rm -f "$RAM_IMG"

    echo "✅ Vault destroyed."
}

case "${1:-setup}" in
    setup)
        setup
        ;;
    teardown)
        teardown
        ;;
    *)
        echo "Usage: $0 {setup|teardown}"
        exit 1
        ;;
esac
