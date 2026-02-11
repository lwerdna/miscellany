#!/usr/bin/env python3

# rename file "foo.txt" to "XXXX foo.txt" where XXXX is the first 4 chars of SHA1

import os
import re
import sys
import base64
import hashlib

def calc_sha1(fpath):
    context = hashlib.sha1()
    with open(fpath, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            context.update(data)

    return context.digest()

def calc_prefix(fpath):
    digest = calc_sha1(fpath)
    temp = base64.b64encode(digest[0:3]) # 24 bits -> 6 bits per b64 char -> 4 chars
    temp = temp.decode('utf-8') # binary -> string
    temp = temp.replace('+', 'X').replace('/', 'X') # don't like these chars
    return temp

if __name__ == '__main__':
    if not sys.argv[1]:
        print(f'supply file name to add to file store')
        sys.exit(-1)

    fpath = sys.argv[1]
    fname = os.path.basename(fpath)
    if not os.path.exists(fpath):
        print(f'given path {fpath} does not exist')

    fname = os.path.basename(fpath)
    fname2 = calc_prefix(fpath) + ' ' + fname
    fpath2 = os.path.join(os.path.dirname(fpath), fname2)
    print(f'{fpath} -> {fpath2}')
