#!/usr/bin/env python3

# rename file "foo.txt" to "foo.txt XXXX" where XXXX is a unique tag for that file

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

# 24-bit tag has 2**24 or ~16 million possibilities
def calc_tag(fpath):
    digest = calc_sha1(fpath)
    temp = base64.b64encode(digest[0:3]) # 24 bits -> 6 bits per b64 char -> 4 chars
    temp = temp.decode('utf-8') # binary -> string
    temp = temp.replace('+', 'X').replace('/', 'X') # don't like these chars, reduce space
    return temp

if __name__ == '__main__':
    if not sys.argv[1:]:
        print(f'supply file name to add a tag to')
        sys.exit(-1)

    fpath = sys.argv[1]
    fname = os.path.basename(fpath)
    if not os.path.exists(fpath):
        print(f'given path {fpath} does not exist')

    fname = os.path.basename(fpath)
    name, ext = os.path.splitext(fname)
    fname2 = name + ' ' + calc_tag(fpath) + ext
    fpath2 = os.path.join(os.path.dirname(fpath), fname2)
    print(f'{fpath} -> {fpath2}')
    #os.rename(fpath, fpath2)
