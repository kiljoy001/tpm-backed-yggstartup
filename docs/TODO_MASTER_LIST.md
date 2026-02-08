# Lux9 Master Todo & Architecture Roadmap

## Active Development (Linux / TPM 2.0)
- [x] **Holographic Vault:** Implement `H(Key | PCR)` derivation for vault mount points.
- [x] **Ephemeral Execution:** Run Yggdrasil from encrypted RAM (tmpfs + dm-crypt).
- [ ] **Systemd Integration:** Finalize `setup-systemd.sh` to install `lux_manager` and `tpm_db.py`.

## Legacy Support (The "Dumpster Node" Initiative)
**Goal:** Enable Lux9 security on legacy hardware (ThinkPad X220, Dell R710, older endpoints) equipped with TPM 1.2.

- **TPM 1.2 Adapter:**
    - Create a hardware abstraction layer in the startup script.
    - Map `tpm2_createprimary` -> `tpm_takeownership` / SRK usage.
    - Map `tpm2_quote` -> `tpm_sealdata` (PCR binding).
    - Map ECC Identity -> RSA 2048 AIK (Attestation Identity Key).
- **Security Considerations:**
    - Acknowledge SHA-1 collision risks for PCRs (acceptable for tamper-evidence).
    - Use RSA Modulus as the seed for the Holographic ID.

## Future Platforms (Ports)

### OpenBSD ("The Fortress")
**Goal:** Port the Lux9 architecture to the most secure OS kernel.
- **Crypto:** Replace `dm-crypt` with `bioctl` + `softraid` on `mfs` (Memory Filesystem).
- **Isolation:** Use `pledge()` and `unveil()` for the daemon process.
- **Tooling:** Port `lux_manager.c` to OpenBSD (native `arc4random`, etc).

### 9front ("The Laboratory")
**Goal:** A purely distributed, namespace-based implementation.
- **Factotum:** Use Plan 9's native key agent instead of a custom DB.
- **9p Fileserver:** Implement the vault not as a block device, but as a synthetic file server (`luxfs`).
- **Browser:** `Mothra` + `QuickJS` (via APE) + `Traitor` + `Plumber` as a decomposed web stack.

## Generalization
- **Generic Vault Tool:** Extract `setup_vault` into a standalone tool (`lux9-mount`) that can wrap ANY service (SSH, Postgres, Wallet) in a holographic integrity vault.
