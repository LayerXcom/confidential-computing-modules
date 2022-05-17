CCMs (Confidential Computing Modules) is a blockchain-agnostic execution environment with privacy and auditability based on TEE (Trusted Execution Environment). CCMs enables flexible execution of business logic while protecting a shared state that is not desired to be revealed to the others. CCMs also provides auditability, i.e., only an auditor can read a specific part of the state. The current implementation of CCMs only supports Ethereum-based blockchains such as [Quorum](https://github.com/jpmorganchase/quorum) as the backend.

Please refer to [White Paper (JP)](https://layerx.co.jp/wp-content/uploads/2020/06/anonify.pdf), [CCMs Book(EN)](https://layerxcom.github.io/anonify-book-en/) / [CCMs Book(JP)](https://layerxcom.github.io/anonify-book/) for more information.

*Note: This is a prototype implementation and has not been tested for production.*

## Setup
Copy environment variables and set your `SPID` and `SUB_KEY`.
```
$ cp .env.sample .env
```

## Running CCMs nodes

### docker
[The ERC20-like application](example/erc20/state-transition/src/lib.rs) is implemented as the initial state transition functions. (Assumed your hardware supports Intel SGX.)

You can build a latest docker image and then run the container:
```
$ docker build -t anonify-server:latest -f docker/server.Dockerfile ./
$ docker run -v /var/run/aesmd:/var/run/aesmd --device /dev/sgx/enclave --env-file ./.env --name anonify -d --rm -it anonify-server:latest
```

### shell scripts

Running nodes
```
$ ./scripts/start-docker.sh
$ cd anonify
$ ./scripts/env-anonify.sh // Change env vars depending on your environment
$ ./scripts/run-server.sh
```

## Using CLI
You can use ccms-cli to communicate with a whole CCMs system. See the [transfer tutorial section](https://layerxcom.github.io/anonify-book-en/Tutorials/ERC20/transfer/) for usage.

Build CCMs's command line utilities.
```
$ ./scripts/build-cli.sh
```

If you want to build artifacts in release mode, pass a `--release` argument.
```
$ ./scripts/build-cli.sh --release
```

## Developing

You can try to build the codebase on your local machine or test it in sgx-enabled environment.

###  Building in simulation mode

CCMs assumes your hardware supports Intel SGX. Without such hardware, you can build it in simulation mode, which allows you to build on macOS.

```
$ docker run -v `pwd`:/root/anonify --rm -it osuketh/anonify:20210310-1804-1.1.3
```

### Testing (ERC20 app)

Assumed your hardware supports Intel SGX or run it on [Azure Confidential Computing](https://azure.microsoft.com/ja-jp/solutions/confidential-compute/), you can test the core component you built works correctly.

The very first thing you need to do is starting aesm service in a SGX-enabled environment. For more details, see: https://github.com/apache/incubator-teaclave-sgx-sdk/blob/master/documents/sgx_in_mesalock_linux.md#solution-overview
```
LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service
```

Running intel SGX environment, and then, you can build in HW mode.
```
$ cd anonify
$ UID=`id -u` GID=`id -g` docker-compose up -d
$ docker-compose exec sgx_machine bash
$ ./scripts/test.sh
```

### Implementation Tips

See [docs/](docs/) to understand code-level architecture.

## Documentations
Currently, documents are only available in Japanese.

- [White Paper](https://layerx.co.jp/wp-content/uploads/2020/06/anonify.pdf)
- [Slides](https://speakerdeck.com/layerx/anonify)
- [CCMs Book(EN)](https://layerxcom.github.io/anonify-book-en/) / [CCMs Book(JP)](https://layerxcom.github.io/anonify-book/)

## License

CCMs is primarily distributed under the terms of the [Apache License (Version 2.0)], see [LICENSE](https://github.com/LayerXcom/confidential-computing-modules/blob/main/LICENSE) for details.
