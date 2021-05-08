#!/usr/bin/env python

import sys
import hashlib
import base64
import requests
from os import getenv

argdata = bytes.fromhex(sys.argv[1])
hashdata = hashlib.sha256(argdata).digest()
value = base64.b64encode(hashdata)

endpoint = getenv('AZ_KV_ENDPOINT')

headers = {
    'Content-Type': 'application/json',
}
data = '{"alg": "RS256", "value": "{value}"}'
response = requests.post(endpoint, headers=headers, data=data)
print(response.json())
