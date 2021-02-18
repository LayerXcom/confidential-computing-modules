#!/bin/bash

which go > /dev/null 2>&1
if [ $? = 1 ]; then
    ./install_go.sh
else
    echo 'go is already installed, skipping installation'
fi

go install github.com/tsenart/vegeta@latest
