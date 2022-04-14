#!/usr/bin/env python3

import os, sys

fpath = sys.argv[1]
lines = []
with open(fpath) as fp:
    lines = fp.readlines()

ext = os.path.splitext(fpath)[1]
fpath_left = f'/tmp/a{ext}'
fpath_right = f'/tmp/b{ext}'

print(f'opening {fpath_left}')
fp_left = open(fpath_left, 'w')
print(f'opening {fpath_right}')
fp_right = open(fpath_right, 'w')

print(f'on line 0, state change: both')
state = 'both'
for (i, line) in enumerate(lines):
    if state == 'both':
        assert not line.startswith('>>>>>>> ')
        assert not line == '=======\n'
        if line.startswith('<<<<<<< '):
            print(f'on line {i+1}, state change: both')
            state = 'left'
        else:
            fp_left.write(line)
            fp_right.write(line)
    elif state == 'left':
        assert not line.startswith('<<<<<<< ')
        assert not line.startswith('>>>>>>> ')
        if line == '=======\n':
            print(f'on line {i+1}, state change: right')
            state = 'right'
        else:
            fp_left.write(line)
    elif state == 'right':
        assert not line.startswith('<<<<<<< ')
        assert not line.startswith('======= ')
        if line.startswith('>>>>>>> '):
            print(f'on line {i+1}, state change: both')
            state = 'both'
        else:
            fp_right.write(line)

fp_left.close()
fp_right.close()

print('conventionally, right is the SOURCE of the merge, left is the DESTINATION')
