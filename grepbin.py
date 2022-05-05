#!/usr/bin/env python

import os
import sys

def find_all(buf, target):
    base = 0
    while True:
        base = buf.find(target, base)
        if base == -1: return
        yield base
        base += 1

target = bytes([int(x,16) for x in sys.argv[2:]])

print(f'searching {sys.argv[0]} for {target}')
with open(sys.argv[1], 'rb') as fp:
    guts = fp.read()
    for offset in find_all(guts, target):
        print(f'{offset:X}: {target}')
