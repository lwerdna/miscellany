#!/usr/bin/env python

# search and replace, in this example:
# * in all Makefiles
# * excluding subdirectory called "./arch/"

import re
import os

for root, dirs, files in os.walk('.'):
    for fname in files:
        #if not re.match(r'^Makefile.*$', fname):
        #    continue
        if not (fname.startswith('ex') and fname.endswith('.html')):
        	continue

        #if (root != '.') and (root[0:7] != './arch/'):
        #    continue

        fpath = os.path.join(root, fname)
        #print "root is: %s" % root
        print("opening %s" % fpath)
        fp = open(fpath, 'r+')
        stuff = fp.read()

        hits = re.findall(r'\.\.\/javascript\/', stuff)
        #hits2 = re.findall(r'\s-O3', stuff)
        total = len(hits)
        if not total:
            fp.close()
            continue

        print("replacing %d instances" % total)

        stuff = re.sub(r'\.\.\/javascript\/', r'', stuff)

        fp.seek(0)
        fp.write(stuff)
        fp.close()

