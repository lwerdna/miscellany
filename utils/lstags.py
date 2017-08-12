#!/usr/bin/env python

import os
import os.path
import sys

if os.path.isfile('tags.py'):
	from tags import lookup
else:
	raise Exception("ERROR: no tags.py found")

# do some stats on tag data
lenMax = 0
tagsAll = {}
for fname in lookup.keys():
	lenMax = max(lenMax, len(fname))
	for t in lookup[fname]:
		
		tagsAll[t] = 1;
	
print 'all tags: ', ''.join(tagsAll.keys())

files = os.listdir('.')

for f in files:
	print f,

	if not (f in lookup):
		continue

	tags = lookup[f]
	print ' '.join(tags)



		
		

