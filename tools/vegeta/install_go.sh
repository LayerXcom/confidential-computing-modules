#!/bin/bash

# `go install` command is available greater than 1.16 version of golang.
GO_VERSION=1.16

wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
ln -s /usr/local/go/bin/go /usr/local/bin/go
ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt

rm -f go${GO_VERSION}.linux-amd64.tar.gz

export PATH=$PATH:$HOME/go/bin
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.profile
