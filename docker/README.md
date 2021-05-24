# Anonify docker files

## Getting Started

Docker images built here are pushed to Azure Container Registry.
In most cases, you just need to pull & run them.

See: [e2e-docker-compose.yml](https://github.com/LayerXcom/anonify/blob/main/e2e-docker-compose.yml).

## Docker Image Development

You just need to edit `docker/*.Dockerfile` and make PR.
CI will automatically build the new docker images and push them to Azure Container Registry.

### Images

- `rust-sgx-sdk-rootless.Dockerfile`
  - Creates root-less version of `baiduxlab/sgx-rust` image. Works as base image for other ones using Rust SGX SDK.
- `dev.Dockerfile`
  - Includes tools to develop anonify (SGX SDK, for example). Used for both SGX HW mode and SW simulation (build-only) mode.
- `erc20.Dockerfile`
- `keyvault.Dockerfile`
