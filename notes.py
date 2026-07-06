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
    valid_commands = ['open', 'edit', 'vim', 'gvim', 'date', 'mark', 'slug']

    fpath = os.path.join(os.environ['HOME'], 'fdumps', 'wiki', 'Commonplace.md')

    cmd = None

    # no arguments? default to opening the notes file
    if not sys.argv[1:]:
        cmd = 'open'
    # but any number of arguments mean the first word is the command
    elif len(sys.argv) == 2 and sys.argv[1] in valid_commands:
        cmd = sys.argv[1]

    if cmd is None:
        line = ' '.join(sys.argv[1:])
        append(fpath, line)

    elif cmd.lower() in ['open', 'edit', 'vim', 'gvim']:
        if platform.system() == 'Darwin':
            line = f'open -a macvim {fpath}'
        else:
            line = 'gvim {fpath}'

        os.system(line)

    elif cmd == 'date':
        if 0:
            date_str = date.today().strftime("%Y-%m-%d_%a")
            line = '<!--' + date + '-->'
        else:
            date_str = date.today().strftime("%Y-%m-%d %A") # xxxx-xx-xx Monday
            line = f'# {date_str}'

        append(fpath, line)

    elif cmd in ['mark', 'slug']:
        words = petname.Generate(3, separator=':').split(':')
        slug = ''.join([w[0].upper() + w[1:] for w in words])
        line = '<!' + '-'*(80 - len(slug) - 5) + slug + '-->'
        append(fpath, line)

