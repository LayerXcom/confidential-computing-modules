<div align="center">
<img src="https://user-images.githubusercontent.com/10915207/81931155-9c178e80-9624-11ea-9a32-5ad7985d1cb3.png" width="400px">
</div>
</br>

Anonify is a blockchain-agnostic execution environment with privacy and auditability based on TEE (Trusted Execution Environment). Currently supported ethereum-based blockchains such as quorum.
It enables high availability and flexible execution of business logic while protecting shared state data that is not desired to be revealed between nodes. It also provides an auditability that allows only a specific audit entity to see the data on the blockchain.

Have a look at [Anonify book](https://layerxcom.github.io/anonify-book/) for usage and more information.

## Setup
Building an anonify contract.
```
$ solc -o build --bin --abi --optimize --overwrite contracts/Anonify.sol
```

## Running anonify system
By using docker-compose, three nodes will be up by default.

```
$ docker-compose -f docker/docker-compose-anonify.yml up -d
```

## Building CLI
You can use anonify-cli to communicate with a whole anonify system.

Build anonify's command line utilities.
```
$ ./scripts/build-cli.sh
```

If you want to build artifacts in release mode, pass a `--release` argument.
```
$ ./scripts/build-cli.sh --release
```

## Documentations
Currently, documents are only available in Japanese.

- [White Paper](https://layerx.co.jp/anonify-white-paper/)
- [Anonify book](https://layerxcom.github.io/anonify-book/)

## License

Anonify is primarily distributed under the terms of the [Apache License (Version 2.0)], see [LICENSE](https://github.com/LayerXcom/anonify/blob/master/LICENSE) for details.