#!/usr/bin/env python

# file tags: list tags, colorized, and quantity in current directory
#
# tags are filename based, like "Lena #woman.jpg" or "catan #boardgame.png"
#
# (see tagspaces "sidecar" option for other tag techniques)

import os
import re
import sys

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(this_dir)
import taglib

tagCount = {}
for root, dirs, fnames in os.walk('.'):
	for dir in dirs:
		pass
	for fname in fnames:
		for tag in re.findall(r'#\w+', fname):
			tagCount[tag] = tagCount.get(tag, 0) + 1

for t in sorted(tagCount, key=lambda x: tagCount[x]):
	print('%s %s%s\x1B[0m' % (str(tagCount[t]).rjust(4), taglib.tag_to_color(t), t))

