#!/usr/bin/env python3

import os
import re
import sys
import time
import random
import tempfile

THREADS_LOC = os.getenv("HOME") + '/fdumps/threads'

def get_iso8601_time():
	seconds = time.time();
	now = time.localtime(seconds)
	return time.strftime("%F", now);

def iso8601_to_epoch(isoString: str):
	time_struct = time.strptime(isoString, '%Y-%m-%d')
	epoch = time.mktime(time_struct)
	return epoch

def epoch_to_iso8601(epoch: float):
	time_struct = time.localtime(epoch)
	time_string = time.strftime('%Y-%m-%d', time_struct)
	return time_string

def long_ago_str(epoch):
    answer = ''
    delta = time.time() - epoch

    if delta < 60:
        answer = '%d sec' % delta
    elif delta < 3600:
        answer = '%d mins' % (delta / 60)
    elif delta < 86400:
        answer = '%d hrs' % (delta / 3600)
    elif delta < 2592000:
        answer = '%d days' % (delta / 86400)
    elif delta < 31536000:
        answer = '%d mos' % (delta / 2592000)
    else:
        answer = '%.1f yrs' % (delta / 31536000.0)

    return answer

def gen_file_path():
	while 1:
		fname = ''.join(random.choices('0123456789', k=8)) + '.md'
		fpath = os.path.join(THREADS_LOC, fname)
		if not os.path.exists(fpath):
			return fpath

def gen_temp_file_path():
	[fd, fpath] = tempfile.mkstemp(suffix='.md')
	os.close(fd)
	return fpath

def parse_thread(fpath):
	with open(fpath, 'r') as fp:
		lines = [x.strip() for x in fp.readlines()]

	title = lines[0]
	epochs = []

	for line in lines:
		if line.startswith('<div style'):
			m = re.match(r'^<div style=.*>Posted (....-..-..)<.*$', line)
			if m:
				epochs.append(iso8601_to_epoch(m.group(1)))

	if not epochs:
		raise Exception('%s had no timestamps' % fpath)

	today = get_iso8601_time()

	num_posts = len(epochs)
	time_c = min(epochs)
	time_m = max(epochs)

	# if modified time was today (coarse YYYY-MM-DD), seek higher resolution (HH:MM:SS) from filesystem
	if epoch_to_iso8601(time_m) == get_iso8601_time():
		time_m = os.path.getmtime(fpath)

	return (title, num_posts, time_c, time_m)

if __name__ == '__main__':
	arg = sys.argv[1] if len(sys.argv)>1 else None

	if arg == 'new':
		fpath = gen_file_path()
		print('writing %s' % fpath)
		with open(fpath, 'w') as fp:
			fp.write('Title of Post\n\n')
			timestamp = get_iso8601_time()

			#tmp = 'Posted %s' % get_iso8601_time()
			#fp.write('<!-- %s -->\n' % tmp)

			line = '<div style="position:absolute; background:lightgrey; width:100%">'
			line += 'Posted %s' % get_iso8601_time()
			line += '</div>\n\n'
			fp.write(line)
		os.system('open %s' % fpath)

	#os.system('open -a macvim "%s"' % fpath)
	#os.system('open -a typora "%s"' % fpath)
	else:
		lookup = {}

		for fname in os.listdir(THREADS_LOC):
			fpath = os.path.join(THREADS_LOC, fname)
			if not fpath.endswith('.md'): continue

			(title, num_posts, ctime, mtime) = parse_thread(fpath)

			lookup[fname] = {
				'fname': fname,
				'fpath': fpath,
				'title': title,
				'ctime': ctime,
				'mtime': mtime,
				'nposts': num_posts,
			}

		fpath = gen_temp_file_path()
		print('writing %s' % fpath)
		with open(fpath, 'w') as fp:
			fp.write('|      | replies | modified |\n')
			fp.write('| ---- | ------- | -------- |\n')

			for fname in sorted(lookup, key=lambda x: lookup[x]['mtime'], reverse=True):
				entry = lookup[fname]

				fp.write('|')
				fp.write('[%s](%s)' % (entry['title'], entry['fpath']))
				fp.write('|')
				fp.write(str(entry['nposts']))
				fp.write('|')
				#fp.write(long_ago_str(entry['ctime']))
				#fp.write('|')
				#fp.write(epoch_to_iso8601(entry['mtime']))
				fp.write(long_ago_str(entry['mtime']))
				fp.write('|\n')

		os.system('open %s' % fpath)





