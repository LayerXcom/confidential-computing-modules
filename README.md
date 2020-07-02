<div align="center">
<img src="https://user-images.githubusercontent.com/10915207/81931155-9c178e80-9624-11ea-9a32-5ad7985d1cb3.png" width="400px">
</div>
</br>

Anonify is a blockchain-agnostic execution environment with privacy and auditability based on TEE (Trusted Execution Environment). Anonify enables flexible execution of business logic while protecting a shared state that is not desired to be revealed to the others. Anonify also provides auditability, i.e., only an auditor can read a specific part of the state. The current implementation of Anonify only supports Ethereum-based blockchains such as [Quorum](https://github.com/jpmorganchase/quorum) as the backend.

Please refer to [Anonify Book(EN)](https://layerxcom.github.io/anonify-book-en/) / [Anonify Book(JP)](https://layerxcom.github.io/anonify-book/) for more information.

*Note: This is a prototype implementation and has not been tested for production.*

## Setup
Building an Anonify contract.
```
$ solc -o contract-build --bin --abi --optimize --overwrite contracts/Anonify.sol
```

## Running anonify protocol
By using docker-compose, three nodes will be up by default. [The ERC20-like application](https://github.com/LayerXcom/anonify/blob/master/example/app/src/lib.rs) is implemented as the initial state transition functions. (Assumed your hardware supports Intel SGX.)

```
$ docker-compose -f docker/docker-compose-anonify.yml up -d
```

## Using CLI
You can use anonify-cli to communicate with a whole anonify system. See the [transfer tutorial section](https://layerxcom.github.io/anonify-book-en/Tutorials/ERC20/transfer/) for usage.

Build Anonify's command line utilities.
```
$ ./scripts/build-cli.sh
```

If you want to build artifacts in release mode, pass a `--release` argument.
```
$ ./scripts/build-cli.sh --release
```

## Developing

###  Building in simulation mode

Anonify assumes your hardware supports Intel SGX. Without such hardware, you can build the core component in simulation mode, which allows you to build on macOS.

```
$ docker run -v `pwd`:/root/anonify --rm -it osuketh/anonify
$ cd anonify/core
$ make DEBUG=1
```

### Testing

Assumed your hardware supports Intel SGX or run it on [Azure Confidential Computing](https://azure.microsoft.com/ja-jp/solutions/confidential-compute/), you can test the core component you built works correctly.

The very first thing you need to do is starting aesm service in a SGX-enabled environment. For more details, see: https://github.com/apache/incubator-teaclave-sgx-sdk/blob/master/documents/sgx_in_mesalock_linux.md#solution-overview
```
LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service
```

If you haven't create a docker network for testing:
```
$ docker network create --subnet=172.18.0.0/16 test-network
```

Running ganache-cli
```
$ docker run -d --name ganache --net=test-network --rm -it trufflesuite/ganache-cli
```

Running intel SGX environment
```
$ ./scripts/start-docker.sh
```

and then, you can build in HW mode.
```
$ cd anonify/core
$ make DEBUG=1
```

Finally, you can test SGX parts.
```
$ cd host
$ cargo test
```

## Documentations
Currently, documents are only available in Japanese.

- [White Paper](https://layerx.co.jp/wp-content/uploads/2020/06/anonify.pdf)
- [Slides](https://speakerdeck.com/layerx/anonify)
- [Anonify Book(EN)](https://layerxcom.github.io/anonify-book-en/) / [Anonify Book(JP)](https://layerxcom.github.io/anonify-book/)

## License

Anonify is primarily distributed under the terms of the [Apache License (Version 2.0)], see [LICENSE](https://github.com/LayerXcom/anonify/blob/master/LICENSE) for details.
