#!/usr/bin/env python3

# make url file

import os
import sys

if not sys.argv[1:]:
    print(f"example: {sys.argv[0]} 'Cool Project' 'http://www.foo.com'")
    sys.exit(-1)

fname = sys.argv[1]
if not fname.endswith('.url'):
    fname += '.url'

url = sys.argv[2]

with open(fname, 'w') as fp:
    fp.write('[InternetShortcut]\n')
    fp.write(f'URL={url}\n')
