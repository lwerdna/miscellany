#!/usr/bin/env python

import os, sys
import glob

a,b = sys.argv[1:3]

a = a + ('/' if not a.endswith('/') else '') + '*'
b = b + ('/' if not b.endswith('/') else '') + '*'

files_a = set([os.path.split(p)[1] for p in glob.glob(a)])
files_b = set([os.path.split(p)[1] for p in glob.glob(b)])

print()

left = files_a - files_b
if left:
    print(f'{a} has {len(left)} files that {b} doesn\'t:')
    print('\n'.join(sorted(left)))

print()

right = files_b - files_a
if right:
    print(f'{b} has {len(right)} files that {a} doesn\'t:')
    print('\n'.join(sorted(right)))

print()

center = files_a.union(files_b)
if center:
    print(f'{b} has {len(center)} in common with {a}:')
    print('\n'.join(sorted(center)))

