#!/usr/bin/env python

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
src = fpaths[0]

dst = os.path.split(src)[1]
if sys.argv[1:]:
	dst = sys.argv[1]

print "copying %s -> %s" % (src, dst)
shutil.copyfile(src, dst)


