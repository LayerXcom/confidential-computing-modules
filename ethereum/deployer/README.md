# Deployer

A command-line utilities for deploying anonify contracts in solidity.

## Usage

```bash
# Deploy a factory contract
cargo run factory

# Deploy a `AnonifyWithTreeKem` or `AnonifyWithEnclaveKey` contract depending on `ANONIFY_ABI_PATH` and `ANONIFY_BIN_PATH` environment variables directly
cargo run anonify_direct

# Deploy a `AnonifyWithTreeKem` contract by the factory contract
cargo run anonify_tk <FACTORY CONTRACT ADDRESS>

# Deploy a `AnonifyWithEnclaveKey` contract by the factory contract
cargo run anonify_ek <FACTORY CONTRACT ADDRESS>
```
