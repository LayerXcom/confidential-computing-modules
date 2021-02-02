# Anonify docker files

In the project root directory, you can build docker files by following commands.
`erc20.Dockerfile` and `keyvault.Dockerfile` can be built in a SGX-enabled environment because it builds in HW mode.

```
// For develop environment in SW or HW mode
$ docker build -t anonify-dev -f docker/dev.Dockerfile ./

// For node containers
$ docker build -t osuketh/anonify-erc20:latest -f docker/erc20.Dockerfile ./
$ docker build -t osuketh/anonify-key-vault:latest -f docker/keyvault.server.Dockerfile ./
```
