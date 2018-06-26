#!/usr/bin/env python

import os
import re
import os.path
import sys
import time
import glob
import random
import shutil
import subprocess

BLOG_LOC = os.getenv("HOME") + '/fdumps/blog'

def get_program_output(argv): # argv like ["identify", "/Users/andrewl/Desktop/Screen Shot 2018-06-25 at 10.40.17 AM.png"]
	print 'running:', ' '.join(argv)
	process = subprocess.Popen(argv, stdout=subprocess.PIPE)
	(output, err) = process.communicate()
	exit_code = process.wait()
	return output

def get_image_size(fpath):
	tmp = get_program_output(['identify', fpath])
	m = re.search(r' (\d+)x(\d+) ', tmp)
	return [int(m.group(1)), int(m.group(2))]

def get_iso8601_time():
	seconds = time.time();
	now = time.localtime(seconds)
	return time.strftime("%F", now);

def get_mtime(fpath):
	struct_stat = os.stat(fpath)
	return time.localtime(struct_stat.st_mtime)

def gen_fname(ext='', nChars=4):
	random.seed()
	lookup = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	fname = ''
	for i in range(nChars):
		fname += lookup[random.randint(0,len(lookup)-1)]
	fname += ext
	return fname

def attach(src, randomize=False):
	fname = os.path.split(src)[1]
	fext = os.path.splitext(src)[1]
	dst = os.path.join(BLOG_LOC, 'attachments', fname)

	while randomize:
		fname = gen_fname(fext)
		dst = os.path.join(BLOG_LOC, 'attachments', fname)
		if not os.path.isfile(dst):
			break

	if os.path.isfile(dst):
		raise Exception('file %s already exists!' % dst)

	print 'src: %s' % src
	print 'dst: %s' % dst
	shutil.copyfile(src, dst)
	return os.path.join('./attachments', fname)

def gen_fname_post():
	i = 0
	time = get_iso8601_time()
	fpath = os.path.join(BLOG_LOC, time + '.md')
	while os.path.exists(fpath):
		fpath = os.path.join(BLOG_LOC, '%s_%02d.md' % (time,i))
		i += 1
	return fpath

def init_post_from_image(fpath):
	fpath_full = attach(fpath, True)

	# see if image is greater width than 640
	fpath_prev = fpath_full
	[width, height] = get_image_size(fpath_full)
	if width > 640:
		fpath_prev = attach(fpath_full, True)
		size_str = '640x%d' % int((640.0/width)*height)
		get_program_output(['mogrify', '-strip', '-resize', size_str, fpath_prev])

	# generate post
	fpath_post = gen_fname_post()
	with open(fpath_post, 'w') as fp:
		fp.write("# Untitled\n\n")
		fp.write("before\n\n");
		fp.write("<a href=\"%s\"><img src=\"%s\"></a>\n" % \
			(fpath_full, fpath_prev));
		fp.write("after\n");

	# edit post
	os.system('open -a typora %s' % fpath_post)

def init_post_from_attach(fpath):
	# attach
	fpath = attach(fpath)

	# generate post
	fpath_post = gen_fname_post()
	with open(fpath_post, 'w') as fp:
		fp.write("# Untitled\n\n")
		fp.write("[original file name %s](%s)\n\n" % (os.path.split(fpath)[1], fpath))

	# edit post
	os.system('open -a typora %s' % fpath_post)

if __name__ == '__main__':

	if len(sys.argv) == 1:
		print 'need arg: ls, new'

	elif sys.argv[1] == 'new':
		os.chdir(BLOG_LOC)
		fpath = gen_fname_post()
		print 'creating: %s' % fpath
		os.system('touch %s' % fpath)
		os.system('open -a typora %s' % fpath)

	elif sys.argv[1] == 'screenshot':
		# attach screenshot, get path
		fpaths = glob.glob(os.environ['HOME'] + "/Desktop/Screen Shot *.png")
		fpaths = sorted(fpaths, key=get_mtime, reverse=True)
		os.chdir(BLOG_LOC)
		init_post_from_image(fpaths[0])

	elif os.path.isfile(sys.argv[1]):
		fpath = os.path.abspath(sys.argv[1])
		os.chdir(BLOG_LOC)
		fname, fext = os.path.splitext(fpath)
		if fext in ['.jpg', '.jpeg', '.gif', '.png']:
			init_post_from_image(fpath)
		else:
			init_post_from_attach(fpath)
	else:
		print 'dunno what to do'
