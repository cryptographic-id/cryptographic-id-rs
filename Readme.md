# cryptographic-id-rs

## Attest the trustworthiness of a device using asymmetric cryptography

This tool was developed to replace `tpm2-totp`. A private-key can be created in the tpm2 and used to sign a message. You can scan the qr-code and verify the signature with [this android app](https://gitlab.com/cryptographic_id/cryptographic-id-flutter/). Although this project supports ed25519-keys saved in files, the tpm2-way (prime256v1 keys) is recommended.

### Installation

Currently there is only a package for Arch Linux available [here](https://aur.archlinux.org/packages/cryptographic-id-rs).

### Usage

To create a key for the initramfs, use `cryptographic_id_add_initramfs`, e.g:

```bash
# cryptographic_id_add_initramfs tpm2 KEY_NAME
Use PCRs? (empty for none or list of pcrs, e.g. 1,7) 7,14
read EC key
writing EC key
SHA2-256(STDIN)= 2E:92:40:7E:2D:2D:1D:ED:93:55:68:2C:81:E8:53:42:B3:0B:43:3D:7F:21:95:31:86:59:43:68:54:D9:BA:C7

Fingerprint:
2E:92:40:7E:2D:2D:1D:ED
93:55:68:2C:81:E8:53:42
B3:0B:43:3D:7F:21:95:31
86:59:43:68:54:D9:BA:C7
```


TODO document measure (environment variables, config file, add config file to Makefile)
what it does, how to enable, how it works

Document apt-get install libtss2-dev dependency



If you don't want to store the sensitive portion of the tpm2-object, you can only save a handle. Keep in mind, if another tool removes the handle from the tpm2, the private-key is lost.
```bash
# cryptographic_id_add_initramfs tpm2 KEY_NAME2 --handle-only
```

To show the qr-codes on boot, add the `cryptographic-id` hook to dracut or mkinitcpio and rebuild the initramfs.

### Configuration

If the qr-codes at boot are too big for your screen, you can specify another console-font name in `/etc/cryptographic_id/initramfs/font`. After all qr-codes are shown, the font will be reset to the original one.

## Why `cryptographic-id` instead of `tpm2-totp`?

`tpm2-totp` uses symmetric cryptography, so every party needs to be in possession of the private key. So if the key cannot be recovered from the tpm2, an attacker could access it on your smartphone. `cryptographic-id` uses asymmetric cryptography, so the key never leaves the tpm2. You can safely have 100 smartphones with the public key stored on it, you can also publish the public-key on the internet.

## Protect tpm2 against clear command

You can protect your tpm2 against the clear command. This can only be undone in the UEFI or if you have the platform auth.
```
tpm2_clearcontrol --hierarchy lockout s
```

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

### Tests

To run the tests, you need swtpm and tpm2-abrmd installed.

```bash
dbus-run-session bash tests/run_test.sh
```

### Security

The rust part of this tool is completely sandboxed using systemd. Please review this project and it's dependencies, but it should be enough to review the shell-scripts and the systemd-service files, if you don't have enough time and don't trust this project or it's dependencies.
