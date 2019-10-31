# anonify
Trusted anonymization layer for any blockchain

## Setup
```
$ docker pull osuketh/anonify
```

## Running Helloworld
```
$ git clone git@github.com:LayerXcom/anonify.git
$ cd anonify
$ docker run -v `pwd`:/root/anonify --rm -it osuketh/anonify
$ cd sgx/helloworld
$ make
$ cd bin
$ ./app
```
