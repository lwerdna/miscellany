#!/usr/bin/env python

# Commonplace tools: merge a commonplace fragment back into the full book

import os

left = '/tmp/CommonplaceFragment.md'
right = os.getenv("HOME") + '/fdumps/wiki/Commonplace.md'
cmd = f'diffmerge {left} {right}'
print(f'running: {cmd}')
os.system(cmd)
