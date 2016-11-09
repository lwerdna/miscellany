#!/usr/bin/python

import re
import os
import sys
import glob
import shutil
from time import localtime, mktime, struct_time

picsdir = '/Volumes/SNAPCAM/DCIM/100SNAPC'
picsjpgs = r'%s/*.JPG' % picsdir
homedir = '/Users/andrewl'
tempdir = '%s/Downloads/temp' % homedir
tempjpgs = r'%s/*.JPG' % tempdir

sys.path.append(os.environ['PATH_ALIB_PY'])
import utils

print "deleting %s" % tempjpgs
g = glob.glob(tempjpgs)
for (i,f) in enumerate(g):
	print 'deleting %s (%d/%d)' % (f, i, len(g))
	os.remove(f)

print "copying while resizing files to ~/Downloads/tmp"
g = glob.glob(picsjpgs)
for (i,srcPath) in enumerate(sorted(g)):
	fname = os.path.basename(srcPath)
	dstPath = os.path.join(tempdir, '%06d.JPG'%i)
	cmd = 'convert %s -resize 640x480 %s' % (srcPath, dstPath)
	print 'calling `%s` (%d/%d)' % (cmd, i, len(g))
	utils.runGetOutput(cmd)

print "encoding files"
cmd = 'ffmpeg -framerate 4 -i %s/%%06d.JPG -c:v libx264 -r 30 -pix_fmt yuv420p out.mp4' % tempdir
print "calling `%s`" % cmd
utils.runGetOutput(cmd)

print "about to delete files from camera! press ctrl+c to quit!"
raw_input()

print "deleting %s" % picsjpgs
g = glob.glob(picsjpgs)
for (i,f) in enumerate(g):
	print 'deleting %s (%d/%d)' % (f, i, len(g))
	os.remove(f)
