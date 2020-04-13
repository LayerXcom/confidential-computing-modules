#!/bin/bash

docker run -v `pwd`:/root/anonify -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket --device /dev/sgx --net=test-network --name sgx --rm -it osuketh/anonify /root/anonify/scripts/build-server-in-docker.sh
