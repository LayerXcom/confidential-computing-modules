# Anonify docker files

## Getting Started

Docker images built here are pushed to Azure Container Registry.
In most cases, you just need to pull & run them.

See: [e2e-docker-compose.yml](https://github.com/LayerXcom/anonify/blob/main/e2e-docker-compose.yml).

## Docker Image Development

You just need to edit `docker/*.Dockerfile` and make PR.
CI will automatically build the new docker images and push them to Azure Container Registry.

### Base Images for development

Should match to the name: `docker/base-*.Dockerfile` in order for CI to build & push only when Dockerfile has been changed.

- `base-rust-sgx-sdk-rootless.Dockerfile`
  - Creates root-less version of `baiduxlab/sgx-rust` image. Works as base image for other ones using Rust SGX SDK.
  - Execute [`fixuid`](https://github.com/boxboat/fixuid) as ENTRYPOINT to avoid permission issue for volume-mounted files.
    - On macOS, set `DISABLE_FIXUID=1` environmental variable because Docker for Mac does user mapping between host and container.
- `base-anonify-dev.Dockerfile`
  - Includes tools to develop anonify (SGX SDK, for example). Used for both SGX HW mode and SW simulation (build-only) mode.
- `base-occlum-enclave.Dockerfile`
  - for developing in the occlum-enable environment
- `base-occlum-host.Dockerfile`
  - for a non-sgx environment to communicate with occlum enclave

#### Example `docker run` command

##### Linux

```bash
docker run -u `id -u`:`id -g` --env-file .env -v `pwd`:/home/anonify-dev/anonify --rm -it anonify.azurecr.io/anonify-dev:latest
```

##### macOS

```bash
$ grep 'DISABLE_FIXUID' .env
DISABLE_FIXUID=1

$ docker run  --env-file .env -v `pwd`:/home/anonify-dev/anonify --rm -it anonify.azurecr.io/anonify-dev:latest
```

### Application Images

Should match to the name: `docker/example-*.Dockerfile` in order for CI to build & push every time main branch has been changed (supposing app codes have been modified).

- `example-erc20.Dockerfile`
- `example-keyvault.Dockerfile`
