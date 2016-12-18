#!/usr/bin/env python

import os
import sys

list_of_files = []
for (dirpath, dirnames, filenames) in os.walk('.'):
	for filename in filenames:
		if filename.endswith('.html'): 
			list_of_files.append(os.sep.join([dirpath, filename]))

for fname in list_of_files:
	fp = open(fname, 'rb')
	stuff = fp.read()
	fp.close()

	stuff = stuff.replace('a href="http://z0mbie.host.sk/', 'a href="')

	fp = open(fname, 'wb')
	fp.write(stuff)
	fp.close()

