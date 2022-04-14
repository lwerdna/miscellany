#!/usr/bin/env python3

import os
import sys

fname = sys.argv[1]
if not fname.endswith('.url'):
    fname += '.url'

url = sys.argv[2]

with open(fname, 'w') as fp:
    fp.write('[InternetShortcut]\n')
    fp.write(f'URL={url}\n')
