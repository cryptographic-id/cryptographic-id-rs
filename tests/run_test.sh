#!/usr/bin/env bash
bash tests/run_with_test_tpm2.sh cargo test --workspace --verbose "${@}"
# cargo test --workspace --verbose --locked
