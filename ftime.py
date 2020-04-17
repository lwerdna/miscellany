#!/usr/bin/env python3

import os, sys, tempfile, subprocess
from time import localtime, mktime, strftime, strptime
fmt = '%Y-%m-%d %H:%M:%S'

if len(sys.argv) < 2:
	raise Exception("required argument: file path")
fpath = sys.argv[1]

# convert to struct_time
struct_stat = os.stat(fpath)
aStruct = localtime(struct_stat.st_atime)
mStruct = localtime(struct_stat.st_mtime)
cStruct = localtime(struct_stat.st_ctime)
#print('old access epoch: %s (%s)' % (mktime(aStruct), strftime(fmt, aStruct)))
#print('old modify epoch: %s (%s)' % (mktime(mStruct), strftime(fmt, mStruct)))
#sys.exit(-1)

data = {}
data['atime'] = strftime(fmt, aStruct)
data['mtime'] = strftime(fmt, mStruct)

# write data to temporary file
(hTmp, pathTmp) = tempfile.mkstemp(suffix='.py')
objTmp = os.fdopen(hTmp, 'w')
objTmp.write(repr(data))
objTmp.close()

# have user edit it
subprocess.call(["vim", '-f', pathTmp])

# read it back
data = ''
with open(pathTmp, 'r') as fd:
	data = fd.read()
data = eval(data)

# change file
aStruct = strptime(data['atime'], fmt)
mStruct = strptime(data['mtime'], fmt)
aEpoch = mktime(aStruct)
mEpoch = mktime(mStruct)

os.utime(fpath, (aEpoch, mEpoch))

os.unlink(pathTmp)

