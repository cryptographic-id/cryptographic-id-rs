# cryptographic-id-rs

## Attest the trustworthiness of a device against a human using asymmetric cryptography

This tool was developed to replace `tpm2-totp`. A private-key can be created in the tpm2 and used to sign a message. You can scan the qr-code and verify the signature with [this android app](https://gitlab.com/cryptographic_id/cryptographic-id-flutter/). Although this project supports ed25519-keys saved in files, the tpm2-way (prime256v1 keys) is recommended.

### Installation

Currently there is only a package for Arch Linux available [here](https://aur.archlinux.org/packages/cryptographic-id-rs).

### Usage

To create a key for the initramfs, use `cryptographic_id_add_initramfs`, e.g:

```bash
cryptographic_id_add_initramfs tpm2 KEY_NAME
```

If you don't want to store the sensitive portion of the tpm2-object, you can only save a handle. Keep in mind, if another tool removes the handle from the tpm2, the private-key is lost.
```bash
cryptographic_id_add_initramfs tpm2 KEY_NAME2 --handle-only
```

To show the qr-codes on boot, add the `cryptographic-id` hook to mkinitcpio and rebuild the initramfs.

## Why `cryptographic-id` instead of `tpm2-totp`?

`tpm2-totp` uses symmetric cryptography, so every party needs to be in possession of the private key. So if the key cannot be recovered from the tpm2, an attacker could access it on your smartphone. `cryptographic-id` uses asymmetric cryptography, so the key never leaves the tpm2. You can safely have 100 smartphones with the public key stored on it, you can also publish the public-key on the internet.

## Development

### Build

To build and run the tool:
```bash
git submodule update --init --recursive
cargo build --release
./target/debug/cryptographic-id-rs --help
```

### Usage

To create a key and sign the identity:
```bash
target/debug/cryptographic-id-rs create path/to/testkey
target/debug/cryptographic-id-rs show path/to/testkey
target/debug/cryptographic-id-rs sign path/to/testkey Message
```

### Security

This tool is completely sandboxed using systemd. Please review this project and it's dependencies, but it should be enough to review the shell-scripts and the systemd-service files, if you don't have enough time and don't trust this project or it's dependencies.
