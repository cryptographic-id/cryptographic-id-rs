# cryptographic-id-rs

## Verify identities based on ed25519-signatures

This is a tool to create an identity based on ed25519 signatures. It can be used to verify a computer (e.g. replace tpm2-otp).

## Build

To build and run the tool:
```bash
git submodule update --init --recursive
cargo build --release
./target/debug/cryptographic-id-rs --help
```

## Usage

To create a key and sign the identity:
```bash
target/debug/cryptographic-id-rs create path/to/testkey
target/debug/cryptographic-id-rs show path/to/testkey
target/debug/cryptographic-id-rs sign path/to/testkey Message
```
