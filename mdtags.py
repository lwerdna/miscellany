#!/usr/bin/env python3

# list tag stats for current directory's markdown files

import os
import re
import sys

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(this_dir)
import taglib

exceptions = ['#print']

tag2count = {}
for fname in filter(lambda x: x.endswith('.md'), os.listdir('.')):
	with open(fname, 'r') as fp:
		lines = fp.readlines()

	for line in lines:
		for tag in re.findall(r'#[a-zA-Z]\w*', line[1:]):
			if tag in exceptions: continue
			tag2count[tag] = tag2count.get(tag, 0) + 1

for t in sorted(tag2count, key=lambda x: tag2count[x]):
	print('%s %s%s\x1B[0m' % (str(tag2count[t]).rjust(4), taglib.tag_to_color(t), t))

