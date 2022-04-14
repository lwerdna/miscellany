#!/usr/bin/env python3

# step1: modify this to apply to files of interest, and before/after string
#     gvim `which replace_in_files`
#
# step2: run to make sure it hits what you think
#     replace_in_files
#
# step3: backup, run with 'really' to make modifications
#     replace_in_files really

import re
import os
import sys

for root, dirs, files in os.walk('.'):
    for fname in files:
        #if not re.match(r'^Makefile.*$', fname): continue
        #if not fname.endswith('.py'): continue
        #if not fname.endswith('.md'): continue
        #if not fname.endswith('.xml'): continue
        if not fname.endswith('.md'): continue

        #if (root != '.') and (root[0:7] != './arch/'):
        #    continue

        fpath = os.path.join(root, fname)
        #print "root is: %s" % root
        print("opening %s" % fpath)

        # text replace
        if 0:
            fp = open(fpath, 'r+')
            stuff = fp.read()

            #hits = re.findall(r'/attachments/', stuff)
            #hits = re.findall(r'usr/bin/env python', stuff)
            #hits = re.findall(r'\s-O3', stuff)
            #before = r'<\?xml-stylesheet type="text/xsl" encoding="UTF-8" href="iform.xsl" version="1.0"\?>'
            #after = '<!-- '+before+' -->'
            before = 'position:absolute; '
            after = ''

            hits = re.findall(before, stuff)
            total = len(hits)
            if not total:
                fp.close()
                continue

            print("\treplacing %d instances" % total)
            stuff = re.sub(before, after, stuff)

            if sys.argv[1:] and sys.argv[1] in ['really', '-really', '--really']:
                fp.seek(0)
                fp.write(stuff)
                fp.close()

        # binary replace
        else:
            fp = open(fpath, 'rb')
            stuff = fp.read()

            #before = b'<script language=\'JavaScript\' type=\'text/javascript\' src=\'http://proxy.host.sk/index.php\'></script>'
            #after = b''
            #before = b'\x0d\x0a' # carriage return ^M, line feed ^J (DOS newline)
            #after = b'\x0a' # line feed ^J (Unix newline)
            before = b'position:absolute; '
            after = b''

            total = stuff.count(before)
            if not total:
                fp.close()
                continue

            print("\treplacing %d instances" % total)
            stuff = stuff.replace(before, after)

            if sys.argv[1:] and sys.argv[1] in ['really', '-really', '--really']:
                fp.close()
                fp = open(fpath, 'wb')
                fp.write(stuff)
                fp.close()

