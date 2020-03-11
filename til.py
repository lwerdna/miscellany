#!/usr/bin/env python3

import os
import re
import sys
import time

TIL_LOC = os.getenv("HOME") + '/fdumps/til'

def get_iso8601_time():
	seconds = time.time();
	now = time.localtime(seconds)
	return time.strftime("%F", now);

if __name__ == '__main__':
	# GET/PROCESS TITLE
	title = input('TITLE: ')
	fname = title.lower()
	#fname = re.sub(r'\W+', '_', fname) # \w is word character, \W is NOT word character
	#fname = re.sub(r'^_+', '', fname) # no leading _
	#fname = re.sub(r'_+$', '', fname) # no trailing _
	fname = fname + '.md'
	fpath = os.path.join(TIL_LOC, fname)

	# WRITE FILE
	print('writing %s' % fpath)
	with open(fpath, 'w') as fp:
		fp.write('\n')
		fp.write('\n')
		fp.write('<!--\n')
		fp.write('\tTAGS: \n')
		fp.write('\tTITLE: %s\n' % title)
		fp.write('\tDATE_CREATED: %s\n' % get_iso8601_time())
		fp.write('\tDATE_MODIFIED: %s\n' % get_iso8601_time())
		fp.write('-->\n')

	# OPEN FILE
	os.system('open -a macvim "%s"' % fpath)
	#os.system('open -a typora %s' % fpath)
