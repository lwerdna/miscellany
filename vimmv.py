#!/usr/bin/env python3

import os
import os.path
import tempfile
import subprocess

RED = '\x1B[31m'
GREEN = '\x1B[32m'
NORMAL = '\x1B[0m'

ignore = ['.DS_Store']
fnames = [x for x in os.listdir('.') if os.path.isfile(x) and not x in ignore]

(tmp_handle, tmp_name) = tempfile.mkstemp(suffix='txt')
print("writing temporary contents to %s" % tmp_name)
tmp_obj = os.fdopen(tmp_handle, 'w')
tmp_obj.write('\n'.join(fnames))
tmp_obj.close()

print("invoking gvim and waiting... (gvim %s)" % tmp_name)
subprocess.call(["vim", '-f', tmp_name])

with open(tmp_name) as fp:
	fnames2 = list(map(lambda x: x.strip(), fp.readlines()))

assert len(fnames) == len(fnames2)
for i in range(len(fnames)):
	before = fnames[i]
	after = fnames2[i]

	if before == after:
		continue

	print('renaming %s%s%s -> %s%s%s' % (RED, before, NORMAL, GREEN, after, NORMAL))
	os.rename(before, after)
