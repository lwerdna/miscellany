#!/usr/bin/env python

# search and replace, in this example:
# * in all Makefiles
# * excluding subdirectory called "./arch/"

import re
import os

for root, dirs, files in os.walk('.'):
    for fname in files:
        if not re.match(r'^Makefile.*$', fname):
            continue

        if (root != '.') and (root[0:7] != './arch/'):
            continue

        fpath = os.path.join(root, fname)
        #print "root is: %s" % root
        print "opening %s" % fpath
        fp = open(fpath, 'r+')
        stuff = fp.read()
        
        hits = re.findall(r'\s-O2', stuff)
        hits2 = re.findall(r'\s-O3', stuff)
        total = len(hits) + len(hits2)
        if not total:
            fp.close()
            continue

        print "replacing %d instances of -O2 or -O3" % total

        stuff = re.sub(r'(\s)-O2', r'\1-O0 -g', stuff)
        stuff = re.sub(r'(\s)-O3', r'\1-O0 -g', stuff)

        fp.seek(0)
        fp.write(stuff)
        fp.close()
                
