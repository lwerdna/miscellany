#!/usr/bin/env python3

# list tag stats for current directory's markdown files

import os
import re
import sys

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(this_dir)
import taglib

# collect tag data
exceptions = ['#print', '#if']
tag2count = {}
tag2files = {}
for fname in filter(lambda x: x.endswith('.md'), os.listdir('.')):
	with open(fname, 'r') as fp:
		lines = fp.readlines()

	for line in lines:
		if not re.match(r'^\s*TAGS:', line):
			continue

		for tag in re.findall(r'#[a-zA-Z]\w*', line):
			if tag in exceptions: continue
			tag2count[tag] = tag2count.get(tag, 0) + 1
			tag2files[tag] = tag2files.get(tag, []) + [fname]

# obey user command
arg = sys.argv[1] if sys.argv[1:] else 'count'
print('arg is: ', arg)

if arg == 'count':
	for t in sorted(tag2count, key=lambda x: tag2count[x]):
		print('%s %s%s\x1B[0m' % (str(tag2count[t]).rjust(4), taglib.tag_to_color(t), t))

elif arg == '-l':
	for t in sorted(tag2count, key=lambda x: tag2count[x]):
		print('%s %s%s\x1B[0m' % (str(tag2count[t]).rjust(4), taglib.tag_to_color(t), t))
		for fname in tag2files[tag]:
			print('\t%s' % fname)

else:
	tag = '#'+arg
	if not tag in tag2count:
		print('no files have that tag')
		sys.exit(0)

	print('%s %s%s\x1B[0m' % (str(tag2count[tag]).rjust(4), taglib.tag_to_color(tag), tag))
	for fname in tag2files[tag]:
		print('\t%s' % fname)

