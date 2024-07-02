#!/usr/bin/env python

# Use this to read Transmission .resume files
# on MacOS: ~/Library/Application Support/Transmission/Resume

import os, sys
import json

# pip install fastbencode
# https://pypi.org/project/fastbencode/
from fastbencode import bencode, bdecode

def decode_all(ds):
    if type(ds) == bytes:
        try:
            return ds.decode('utf-8')
        except UnicodeDecodeError:
            return f'(couldn\'t utf-8 decode {len(ds)} bytes)'

    if type(ds) == dict:
        return {decode_all(k):decode_all(v) for k,v in ds.items()}

    if type(ds) == list:
        return [decode_all(x) for x in ds]

    return ds

if __name__ == '__main__':
    fpath = sys.argv[1]

    with open(fpath, 'rb') as fp:
        data = fp.read()

    datastruct = bdecode(data)

    datastruct = decode_all(datastruct)

    #print(datastruct)

    print(json.dumps(datastruct, indent=4))

