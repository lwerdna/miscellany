#!/usr/bin/python

import re
import os
import sys
import glob
import shutil
from time import localtime, mktime, struct_time

picsdir = '/Volumes/snapcam/DCIM/100SNAPC'
picsjpgs = r'%s/*.JPG' % picsdir
homedir = '/Users/andrewl'
tempdir = '%s/Downloads/temp' % homedir
tempjpgs = r'%s/*.JPG' % tempdir

sys.path.append(os.environ['PATH_ALIB_PY'])
import utils

print "finding start number"
g = glob.glob(picsjpgs)
startNum = None
for fpath in g:
	m = re.match(r'^.*SNAP(\d+)', fpath)
	i = int(m.group(1))
	if not startNum or i < startNum:
		startNum = i
print 'start number is: %d' % startNum

print "deleting %s" % tempjpgs
g = glob.glob(tempjpgs)
for (i,f) in enumerate(g):
	print 'deleting %s (%d/%d)' % (f, i, len(g))
	os.remove(f)

print "copying while resizing files to ~/Downloads/tmp"
g = glob.glob(picsjpgs)
for (i,srcPath) in enumerate(g):
	fname = os.path.basename(srcPath)
	dstPath = os.path.join(tempdir, fname)
	cmd = 'convert %s -resize 640x480 %s' % (srcPath, dstPath)
	print 'calling `%s` (%d/%d)' % (cmd, i, len(g))
	utils.runGetOutput(cmd)

print "encoding files"
cmd = 'ffmpeg -framerate 4 -start_number %d -i %s/SNAP%%04d.JPG -c:v libx264 -r 30 -pix_fmt yuv420p out.mp4' % (startNum, tempdir)
print "calling `%s`" % cmd
utils.runGetOutput(cmd)

print "about to delete files from camera! press ctrl+c to quit!"
raw_input()

print "deleting %s" % picsjpgs
g = glob.glob(picsjpgs)
for (i,f) in enumerate(g):
	print 'deleting %s (%d/%d)' % (f, i, len(g))
	#os.remove(f)
