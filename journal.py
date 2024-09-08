#!/usr/bin/env python

import os
import time

def epochToISO8601(epoch: float):
    timeStruct = time.localtime(epoch)
    timeString = time.strftime('%Y-%m-%d', timeStruct)
    return timeString

prefix = epochToISO8601(time.time()) # like "2024-07-09"
path = os.path.join(os.environ['HOME'], 'fdumps', 'journals')
print(f'looking in {path}')

found = None
for fname in os.listdir(path):
    if fname.startswith(prefix):
        found = os.path.join(path, fname)
        print(f'found existing journal for today: {found}')
        break
else:
    found = os.path.join(path, prefix + '.md')
    print(f'creating new journal for today: {found}')
    os.system('touch ' + found) 

print(f'opening: {found}')
os.system('open -a typora ' + found)
