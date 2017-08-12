#!/usr/bin/env python

import os
import subprocess
from cp437 import getImgLine, getImgString

delay = 100 # in 100'ths of second

def setDelay(delay_):
	global delay
	delay = delay_

def write(framesTxt, fnameOut):
	global delay

	# convert text frames -> image frames
	framesImg = []
	for f in framesTxt:
		framesImg.append(getImgString(f))
	
	# map images frames -> file names
	framesFname = []
	for (i, img) in enumerate(framesImg):
		fname = 'frame%04d.png' % i
		print "writing %s" % fname
		img.save(fname)
		framesFname.append(fname)
	
	# call imagemagick
	print "calling imagemagick"
	args = ['convert']
	args += ['-delay', '%d' % delay]
	args += ['-loop', '0']
	args += framesFname
	args.append(fnameOut)
	print "executing: ", args
	subprocess.call(args)
	
	# delete temporary files
	for fname in framesFname:
		print "deleting %s" % fname
		os.unlink(fname)

