#!/usr/bin/env python3

# add print()'s after every function definition

import re
import os
import sys

print('WARNING: this will modify all python files in current directory and children')
print('ctrl+c now to abort')
input()

for root, dirs, files in os.walk('.'):
	for fname in files:
		if not fname.endswith('.py'): continue

		# read lines
		fpath = os.path.join(root, fname)
		print("opening %s" % fpath)
		fp = open(fpath, 'r+')
		lines = fp.readlines()

		# make new lines
		tmp = []
		for (i,line) in enumerate(lines):
			tmp.append(line)

			m = re.match(r'^\s*def ([^\(]+)', line)
			if m:
				fname = m.group(1)
				if fname in ['__init__', '__repr__']:
					continue
				space = re.match(r'^(\s*)', lines[i+1]).group(1)
				foo = space + 'print(\'%s %s()\')\n' % (fpath, fname)
				print('adding: %s' % foo)
				tmp.append(foo)
		lines = tmp

		# write to file
		fp.seek(0)
		for line in lines:
			fp.write(line)
		fp.close()

