#!/usr/bin/env python3

# add print()'s after every function definition

import re
import os
import sys

fpaths = []
if sys.argv[1:]:
    fpaths = [sys.argv[1]]
else:
    print('WARNING: this will modify all python files in current directory and children')
    print('ctrl+c now to abort')
    input()

    for root, dirs, fpaths in os.walk('.'):
        for fname in fpaths:
            if not fname.endswith('.py'): continue
            fpath = os.path.join(root, fname)
            fpaths.append(fpath)

for fpath in fpaths:
    # read lines
    print("opening %s" % fpath)
    fp = open(fpath, 'r+')
    lines = fp.readlines()

    # make new lines
    tmp = []
    for (i,line) in enumerate(lines):
        tmp.append(line)

        m = re.match(r'^\s*def ([^\(]+)', line)
        if m:
            fname = m.group(1)
            if fname in ['__init__', '__repr__']:
                continue
            space = re.match(r'^(\s*)', lines[i+1]).group(1)
            foo = space + 'print(\'%s %s()\')\n' % (fpath, fname)
            print('adding: %s' % foo)
            tmp.append(foo)
    lines = tmp

    # write to file
    fp.seek(0)
    for line in lines:
        fp.write(line)
    fp.close()

