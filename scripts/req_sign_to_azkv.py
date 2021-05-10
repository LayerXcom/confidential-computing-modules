#!/usr/bin/env python

import sys
import hashlib
import base64
import os
from azure.keyvault.keys.crypto import SignatureAlgorithm, CryptographyClient
from azure.identity import DefaultAzureCredential

# Generate a signing material for Azure Keyvault
path_r = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../.anonify/{}.dat'.format(sys.argv[1]))
with open(path_r, mode='rb') as f:
    data = f.read()
digest = hashlib.sha256(data).digest()

# Signed by Azure Keyvault
# ref: https://docs.microsoft.com/en-us/python/api/overview/azure/keyvault-keys-readme?view=azure-python
credential = DefaultAzureCredential()
endpoint = os.environ.get('AZ_KV_ENDPOINT')
# ref: https://docs.microsoft.com/en-us/python/api/azure-keyvault-keys/azure.keyvault.keys.crypto.cryptographyclient?view=azure-python#sign-algorithm--digest----kwargs-
crypto_client = CryptographyClient(endpoint, credential)
response = crypto_client.sign(SignatureAlgorithm.rs256, digest)

print("Successfully signed by Azure Keyvault")

# Save the signature
path_w = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../.anonify/{}_signed.dat'.format(sys.argv[1]))
with open(path_w, mode='wb') as f:
    f.write(response.signature)
