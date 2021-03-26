# Deployer
A command-line utilities for deploying anonify contracts in solidity.

## Usage

```
# Deploy a factory contract
cargo run factory

# Deploy a `AnonifyWithTreeKem` contract directly
cargo run anonify_tk_direct

# Deploy a `AnonifyWithEnclaveKey` contract directly
cargo run anonify_ek_direct

# Deploy a `AnonifyWithTreeKem` contract by the factory contract
cargo run anonify_tk <FACTORY CONTRACT ADDRESS>

# Deploy a `AnonifyWithEnclaveKey` contract by the factory contract
cargo run anonify_ek <FACTORY CONTRACT ADDRESS>
```
