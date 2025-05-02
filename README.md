# TPM-Secured Yggdrasil Launcher

A security-enhanced deployment tool that protects Yggdrasil networking keys using Trusted Platform Module (TPM) hardware.

## Features

* **Hardware Security**: Stores private keys securely in TPM hardware rather than on disk
* **In-Memory Configuration**: Runs Yggdrasil with configuration loaded only in RAM
* **Zero Persistence**: Leaves no sensitive data on disk after shutdown
* **Secure Cleanup**: Uses military-grade shredding to wipe temporary files
* **Random TPM Handles**: Generates unpredictable TPM object handles for enhanced security
* **Fault Tolerance**: Recovers from previous states using stored metadata

## How It Works

This script creates a secure environment for Yggdrasil networking by:

1. Generating or retrieving TPM object handles
2. Creating a primary TPM key if needed
3. Generating an ephemeral Yggdrasil configuration in RAM
4. Sealing the private key into the TPM
5. Launching Yggdrasil with the secured configuration
6. Monitoring the process and cleaning up when it exits

## Benefits

* Protects against filesystem-based key theft
* Defends against memory-scraping attacks through secure cleanup
* Works with standard TPM 2.0 hardware
* Fully automated operation with error handling
* Preserves key material across reboots without leaving it exposed

Ideal for servers and devices that require maximum security for Yggdrasil mesh networking deployments.
