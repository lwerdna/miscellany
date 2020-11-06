#!/usr/bin/env python

import os
import re
import sys
import time
import random
import pickle
from termcolor import cprint

PATH_KB = os.path.join(os.environ['PATH_KB'])
PATH_KBDATA = os.path.join(PATH_KB, 'kbdata.bin')
os.chdir(PATH_KB)
database = {}
# schema:
# {
#	<fname>: {
#				'mtime': file modification time (float),
#				'date_created': creation time (float),
#				'date_edited': edit time (float),
#				'tags': tags (list),
#			}
# }

#------------------------------------------------------------------------------
# time conversion
#------------------------------------------------------------------------------

def epochToISO8601(epoch: float):
	if epoch == None:
		return 'None'
	if epoch == 'now':
		epoch = None
	time_struct = time.localtime(epoch)
	time_string = time.strftime('%Y-%m-%d', time_struct)
	return time_string

def ISO8601ToEpoch(isoString: str):
	time_struct = time.strptime(isoString, '%Y-%m-%d')
	epoch = time.mktime(time_struct)
	return epoch

#------------------------------------------------------------------------------
# database handling
#------------------------------------------------------------------------------

def db_load():
	global PATH_KBDATA, database
	with open(PATH_KBDATA, 'rb') as fp:
		database = pickle.load(fp)

def db_save():
	global PATH_KBDATA, database
	with open(PATH_KBDATA, 'wb') as fp:
		pickle.dump(database, fp)

def db_update():
	global PATH_KB, database
	db_load()

	fnames = os.listdir(PATH_KB)
	for fname in fnames:
		if not (fname.endswith('.md') or fname.endswith('.txt')):
			continue

		if not fname in database:
			cprint('adding %s' % fname, 'green')
		else:	
			mtime_fs = os.path.getmtime(fname)
			mtime_db = 0
			if fname in database and 'mtime' in database[fname]:
				mtime_db = database[fname]['mtime']
			if mtime_db >= mtime_fs: # database is current
				continue
			cprint('updating %s' % fname, 'yellow')

		database[fname] = {
			'mtime': mtime_fs,
			'date_created': get_date_created(fname),
			'date_edited': get_date_edited(fname),
			'tags': get_tags(fname),
		}

	# do we have anything files in the database that no longer exist on disk?
	for fname in [x for x in database if not x in fnames]:
		cprint('forgetting %s, as it doesn\'t exist on disk' % fname, 'red')
		del database[fname]

	db_save()

def db_print(fname):
	global database
	db_load()

	fnames = [fname] if fname else sorted(database)
	for fname in fnames:
		print(fname)
		print('\t        mtime: %s' % epochToISO8601(database[fname]['mtime']))
		print('\t date_created: %s' % epochToISO8601(database[fname]['date_created']))
		print('\t  date_edited: %s' % epochToISO8601(database[fname]['date_edited']))
		print('\t         tags: %s' % database[fname]['tags'])

	print('%d files listed' % len(fnames))

#------------------------------------------------------------------------------
# file parsing stuff
#------------------------------------------------------------------------------

def get_tags(fname):
	return []

# attempt to infer when the file was created
# - look for front matter
# - look for metadata in comments
# - look for html log divs
# returns:
#	time, epoch convention, type float
def get_date_created(fname):
	with open(fname, 'r') as fp:
		data = fp.read()

	# if the file is marked, either in frontmatter or html comments
	m = re.search(r'DATE_CREATED: (\d\d\d\d-\d\d-\d\d)', data)
	if m:
		return ISO8601ToEpoch(m.group(1))

	# else, see if there's an html log entry
	oldest = None
	for datestr in re.findall(r'>Posted (\d\d\d\d-\d\d-\d\d)</div>', data):
		tmp = ISO8601ToEpoch(datestr)
		if oldest == None or tmp > oldest:
			oldest = tmp
	if oldest:
		return oldest
	
	# else we can only sort it last
	return 0;

# attempt to infer when file was modified (NOT thru file system)
def get_date_edited(fname):
	with open(fname, 'r') as fp:
		data = fp.read()

	# are there a series of html log entries?
	newest = None
	for datestr in re.findall(r'>Posted (\d\d\d\d-\d\d-\d\d)</div>', data):
		tmp = ISO8601ToEpoch(datestr)
		if newest == None or tmp > newest:
			newest = tmp
	if newest:
		return newest

	# if the file is marked, either in frontmatter or html comments
	m = re.search(r'DATE_MODIFIED: (\d\d\d\d-\d\d-\d\d)', data)
	if m:
		return ISO8601ToEpoch(m.group(1))

	# else, the edit date is the created data
	return get_date_created(fname)

#------------------------------------------------------------------------------
# output stuff
#------------------------------------------------------------------------------

def four_column(fnames):
	global database

	#fnames = sorted(fnames, key=lambda x: database[x]['date_edited'])
	fnames = sorted(fnames)

	while fnames:
		line = ''
		for fname in fnames[0:4]:
			tmp = fname.ljust(32)
			line += tmp
			if len(tmp) > 32:
				break

		print(line)
		fnames = fnames[4:]

def perform_ls(limit):
	global database
	db_load()

	seen = set()
	width = os.get_terminal_size().columns
	now = ISO8601ToEpoch(epochToISO8601('now'))

	time_thresholds = [
		(now-24*3600, 'LAST DAY'),
		(now-7*24*3600, 'LAST WEEK'),
		(now-30*24*3600, 'LAST MONTH'),
		(now-4*30*24*3600, 'LAST QUARTER'),
		(now-365*24*3600, 'LAST YEAR'),
		(now-3*365*24*3600, 'LAST THREE YEARS'),
		(0, 'REMAINDER')
	]

	for (threshold, description) in time_thresholds:
		collection = [x for x in database if database[x]['date_edited'] >= threshold and not x in seen]
		if collection:
			if len(seen)>0:
				print()
			cprint(description.center(width, ' '), 'white', 'on_blue')
			four_column(collection)
		seen.update(collection)
		if len(seen) > limit:
			break

#------------------------------------------------------------------------------
# new post stuff
#------------------------------------------------------------------------------

def gen_fname(ext='.md', n_chars=8):
	global PATH_KB
	random.seed()

	while True:
		#lookup = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		lookup = '0123456789';
		fname = ''
		for i in range(n_chars):
			fname += lookup[random.randint(0,len(lookup)-1)]
		if ext.startswith('.'):
			fname += ext
		else:
			fname = '%s.%s' % (fname, ext)
		if not os.path.exists(fname):
			return fname

def new_post(extension):
	global PATH_KB
	fname = gen_fname(extension)

	now_str = epochToISO8601('now')

	print('writing %s' % fname)
	with open(fname, 'w') as fp:
		fp.write('---\n')
		fp.write('DATE_CREATED: %s\n' % now_str)
		fp.write('DATE_MODIFIED: %s\n' % now_str)
		fp.write('TAGS: []\n')
		fp.write('---\n')
		fp.write('\n')

	return fname

if __name__ == '__main__':
	cmd = ''
	if sys.argv[1:]:
		cmd = sys.argv[1]

	arg0 = None
	if sys.argv[2:]:
		arg0 = sys.argv[2]

	if cmd == 'update':
		db_update()
	elif cmd == 'forget':
		database = {}
		db_save()
	elif cmd == 'print':
		fname = None
		if sys.argv[2:]:
			fname = sys.argv[2]
		db_print(fname)
	elif cmd == 'ls':
		perform_ls(100)
	elif cmd == 'lsall':
		perform_ls(1000000)
	elif cmd == 'new':
		fname = new_post('md')
		os.system('open -a macvim %s' % fname)

