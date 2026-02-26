#!/usr/bin/env python3

import os
import re
import sys
import base64
import random
import platform
from datetime import date

import petname

def append(fpath, line):
    print(f'appending: {line}')
    with open(fpath, "a") as f:
        f.write('\n' + line + '\n')

if __name__ == '__main__':
    fpath = os.path.join(os.environ['HOME'], 'fdumps', 'notes', 'notes.txt')

    cmd = 'open'
    if sys.argv[1:]:
        cmd = sys.argv[1]

    if cmd.lower() in ['open', 'edit', 'vim', 'gvim']:
        if platform.system() == 'Darwin':
            line = f'open -a macvim {fpath}'
        else:
            line = 'gvim {fpath}'

        os.system(line)

    elif cmd == 'date':
        date = date.today().strftime("%Y-%m-%d_%a")
        line = '<!--' + date + '-->'
        append(fpath, line)

    elif cmd in ['mark', 'slug']:
        words = petname.Generate(3, separator=':').split(':')
        slug = ''.join([w[0].upper() + w[1:] for w in words])
        line = '<!' + '-'*(80 - len(slug) - 5) + slug + '-->'
        append(fpath, line)

