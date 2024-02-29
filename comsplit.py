#!/usr/bin/env python

# Commonplace tools: split off the book into a fragment to ease editing

import re
import os
import sys
import time

FPATH = os.getenv("HOME") + '/fdumps/wiki/Commonplace.md'

def iso8601_to_epoch(isoString: str):
	time_struct = time.strptime(isoString, '%Y-%m-%d')
	epoch = time.mktime(time_struct)
	return epoch

with open(FPATH, 'r') as fp:
    lines = fp.readlines()

epoch_now = time.time()
print(f'epoch now: {epoch_now}')

cutoff = None

if not sys.argv[1:] or sys.argv[1] == 'week':
    epoch_ago = epoch_now - 7*24*60*60
    print(f'epoch 1 week ago: {epoch_ago}')
    for i,line in enumerate(lines):
        if m := re.match(r'^# (\d\d\d\d-\d\d-\d\d).*$', line):
            epoch = iso8601_to_epoch(m.group(1))
            print(f'Is {epoch} >= {epoch_ago} ? {epoch >= epoch_ago}')
            if epoch >= epoch_ago:
                cutoff = i
                break

if cutoff == None:
    print(f'ERROR: not found')
else:
    print(f'Found on line {cutoff}')
    fpath = '/tmp/CommonplaceFragment.md'
    print(fpath)
    with open(fpath, 'w') as fp:
        fp.write(f'---\n')
        fp.write(f'typora-copy-images-to: ./assets\n')
        fp.write(f'---\n')
        fp.write(f'\n')
        fp.write(''.join(lines[cutoff:]))

    cmd = 'open -a typora %s' % fpath
    print(f'running: {cmd}')
    os.system(cmd)
