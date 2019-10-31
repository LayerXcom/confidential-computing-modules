# anonify
Trusted anonymization layer for any blockchain

## Setup
```
$ docker pull osuketh/anonify
```

## Running Helloworld
This tutorial works in simulation mode, so you can run it on macos.

```
$ git clone git@github.com:LayerXcom/anonify.git
$ cd anonify
$ docker run -v `pwd`:/root/anonify --rm -it osuketh/anonify
$ cd anonify/helloworld
$ make
$ cd bin
$ ./app
```
