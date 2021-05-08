#!/usr/bin/env python

import sys
import hashlib
import base64
import requests
import os
from azure.keyvault.keys.crypto import SignatureAlgorithm

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../.anonify/{}.hex'.format(sys.argv[1]))
with open(path, mode='rb') as f:
    data = f.read()

digest = hashlib.sha256(data).digest()
# ref: https://docs.microsoft.com/en-us/python/api/azure-keyvault-keys/azure.keyvault.keys.crypto.cryptographyclient?view=azure-python#sign-algorithm--digest----kwargs-

value = base64.b64encode(hashdata)

endpoint = os.environ.get('AZ_KV_ENDPOINT')
headers = {
    'Content-Type': 'application/json',
}
data = '{"alg": "RS256", "value": "{value}"}'
response = requests.post(endpoint, headers=headers, data=data)
print(response.json())
