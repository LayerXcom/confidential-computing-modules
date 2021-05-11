#!/bin/bash

set -e

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../config"

cp -f Enclave.config.xml Enclave.prd.config.xml
sudo chmod 766 Enclave.prd.config.xml
sed -i "" -e "s|<ProdID>0</ProdID>|<ProdID>${PROD_ID}</ProdID>|" Enclave.prd.config.xml
sed -i "" -e "s|<ISVSVN>0</ISVSVN>|<ISVSVN>${ISVSVN}</ISVSVN>|" Enclave.prd.config.xml
sed -i "" -e "s|<DisableDebug>0</DisableDebug>|<DisableDebug>1</DisableDebug>|" Enclave.prd.config.xml
