#!/usr/bin/env python3

import os
import sys
import glob
import time
import shutil

def get_mtime(fpath):
    struct_stat = os.stat(fpath)
    return time.localtime(struct_stat.st_mtime)

fpaths = glob.glob(os.environ['HOME'] + "/Downloads/*")
fpaths = sorted(fpaths, key=get_mtime, reverse=True)

if len(sys.argv) < 2:
    print('Listing last 10 downloads:')
    print('\n'.join(fpaths[0:10]))
    print('use `%s ./foo.png` to copy latest download here' % sys.argv[0])
else:
    src = fpaths[0]
    dst = sys.argv[1]

    if dst == '.':
        (_, fname) = os.path.split(src)
        dst = os.path.join(os.getcwd(), fname)

    print(f'copying...\nsrc: {src}\ndst: {dst}')
    shutil.copyfile(src, dst)


