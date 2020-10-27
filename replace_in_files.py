#!/usr/bin/env python3

# step1: modify this to apply to files of interest, and before/after string
# 	gvim `which replace_in_files`
#
# step2: run to make sure it hits what you think
# 	replace_in_files
#
# step3: backup, run with 'really' to make modifications
# 	replace_in_files really

import re
import os
import sys

for root, dirs, files in os.walk('.'):
	for fname in files:
		#if not re.match(r'^Makefile.*$', fname): continue
		#if not fname.endswith('.py'): continue
		#if not fname.endswith('.md'): continue
		if not fname.endswith('.xml'): continue

		#if (root != '.') and (root[0:7] != './arch/'):
		#	continue

		fpath = os.path.join(root, fname)
		#print "root is: %s" % root
		print("opening %s" % fpath)
		fp = open(fpath, 'r+')
		stuff = fp.read()

		#hits = re.findall(r'/attachments/', stuff)
		#hits = re.findall(r'usr/bin/env python', stuff)
		#hits = re.findall(r'\s-O3', stuff)
		before = r'<\?xml-stylesheet type="text/xsl" encoding="UTF-8" href="iform.xsl" version="1.0"\?>'
		after = '<!-- '+before+' -->'
		hits = re.findall(before, stuff)
		total = len(hits)
		if not total:
			fp.close()
			continue

		print("\treplacing %d instances" % total)

		if sys.argv[1:] and sys.argv[1] == 'really':
			stuff = re.sub(before, after, stuff)
			fp.seek(0)
			fp.write(stuff)
			fp.close()

