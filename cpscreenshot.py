#!/usr/bin/env python3

import os
import sys
import glob
import time
import shutil

def get_mtime(fpath):
    struct_stat = os.stat(fpath)
    return time.localtime(struct_stat.st_mtime)

fpaths = []
fpaths += glob.glob(os.environ['HOME'] + "/Desktop/Screen Shot *.png")
fpaths += glob.glob(os.environ['HOME'] + "/Desktop/Screenshot *.png")

fpaths = sorted(fpaths, key=get_mtime, reverse=True)

if len(sys.argv) < 2:
    print('Listing all available screenshots:')
    print('\n'.join(fpaths))
    print('use `%s ./foo.png` to copy latest screenshot here' % sys.argv[0])
else:
    src = fpaths[0]
    dst = sys.argv[1]

    print("copying %s -> %s" % (src, dst))
    shutil.copyfile(src, dst)


