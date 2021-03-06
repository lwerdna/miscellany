#!/usr/bin/env python

# KB (knowledge base) library, used by CLI and GUI interfaces

import os
import re
import sys
import time
import random
import shutil
import pickle
from termcolor import cprint

PATH_KB = os.path.join(os.environ['PATH_KB'])
PATH_KBDATA = os.path.join(PATH_KB, 'kbdata.bin')
os.chdir(PATH_KB)
database = {}
# schema:
# {
#	<fname>: {
#				'fpath': path (string)
#				'title': title (string),
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
# front matter
#------------------------------------------------------------------------------

def parse_list(code):
	assert code.startswith('[') and code.endswith(']')
	code = code[1:-1]
	code = code.split(',')
	code = [c.strip() for c in code]
	return code

def read_front_matter(fpath):
	# { 'DATE_CREATED': '2020-12-15',
	#   'DATE_MODIFIED': '2020-12-17',
	#   'TAGS': ['foo', 'bar', 'baz']
	# }
	result = {}

	with open(fpath) as fp:
		lines = [l.strip() for l in fp.readlines()]

	if not lines[0]=='---':
		return result

	for i in range(1, len(lines)):
		line = lines[i].strip()
		if line == '---':
			break
		m = re.match('^\s*(\w+)\s*:\s*(.*)$', line)
		assert m, 'malformed front matter: %s' % line
		(var_name, var_val) = m.group(1,2)
		if var_val.startswith('['):
			var_val = parse_list(var_val)
		result[var_name] = var_val

	return result

def write_front_matter(fpath, fm):
	with open(fpath) as fp:
		lines = [l.strip() for l in fp.readlines()]

	if lines[0]=='---':
		lines = lines[1:]
		tmp = lines.index('---')
		lines = lines[tmp+1:]

	fmlines = ['---']
	for(name, value) in sorted(fm.items()):
		if type(value) == list:
			value = '[' + ','.join([str(x) for x in value]) + ']'
		else:
			value = str(value)
		fmlines.append('%s: %s' % (name, str(value)))
	fmlines.append('---')

	lines = fmlines + lines
	with open(fpath, 'w') as fp:
		fp.write('\n'.join(lines))

def set_front_matter_title(fname, title):
	fpath = os.path.join(PATH_KB, fname)
	fm = read_front_matter(fpath)
	fm['TITLE'] = title
	write_front_matter(fpath, fm)

# tags is like: ['one', 'two', 'three']
def set_front_matter_tags(fname, tags):
	fpath = os.path.join(PATH_KB, fname)
	fm = read_front_matter(fpath)
	fm['TAGS'] = tags
	write_front_matter(fpath, fm)


#------------------------------------------------------------------------------
# file parsing stuff
#------------------------------------------------------------------------------

def get_tags(fname):
	fm = read_front_matter(fname)
	if 'tags' in fm: return fm['tags']
	if 'TAGS' in fm: return fm['TAGS']
	return []

def get_title(fname):
	fm = read_front_matter(fname)
	if 'title' in fm: return fm['title']
	if 'TITLE' in fm: return fm['TITLE']
	return 'Untitled'

# attempt to infer when the file was created
# - look for front matter
# - look for metadata in comments
# - look for html log divs
# returns:
#	time, epoch convention, type float
def get_date_created(fname):
	with open(fname, 'r') as fp:
		data = fp.read()

	# frontmatter has highest priority
	m = re.search(r'DATE_CREATED: (\d\d\d\d-\d\d-\d\d)', data)
	if m:
		return ISO8601ToEpoch(m.group(1))

	# else, filesystem and log entries battle
	#oldest = os.path.getctime(fname);
	oldest = os.stat(fname).st_birthtime
	for datestr in re.findall(r'>Posted (\d\d\d\d-\d\d-\d\d)</div>', data):
		tmp = ISO8601ToEpoch(datestr)
		if oldest == None or tmp < oldest:
			oldest = tmp
	return oldest

# attempt to infer when file was modified
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

	# else, the edit date is the file modification time
	return os.path.getmtime(fname)

#------------------------------------------------------------------------------
# database handling
#------------------------------------------------------------------------------

# load kb database from disk, return dictionary
def db_load():
	global PATH_KBDATA
	with open(PATH_KBDATA, 'rb') as fp:
		return pickle.load(fp)

# save kb database to disk
def db_save(database):
	global PATH_KBDATA
	with open(PATH_KBDATA, 'wb') as fp:
		pickle.dump(database, fp)

# update kb database on disk with newly parsed file info
def db_update(force=False):
	global PATH_KB
	database = db_load()

	fnames = os.listdir(PATH_KB)
	for fname in fnames:
		if not (fname.endswith('.md') or fname.endswith('.txt')):
			continue

		mtime_fs = os.path.getmtime(fname)

		if not fname in database:
			cprint('adding %s' % fname, 'green')
		else:
			mtime_db = 0
			if fname in database and 'mtime' in database[fname]:
				mtime_db = database[fname]['mtime']
			if mtime_db >= mtime_fs and not force: # database is current
				continue
			cprint('updating %s' % fname, 'yellow')

		fpath = os.path.join(PATH_KB, fname)
		database[fname] = {
			'fname': fname,
			'fpath': fpath,
			'fsize': os.path.getsize(fpath),
			'title': get_title(fname),
			'mtime': mtime_fs,
			'date_created': get_date_created(fname),
			'date_edited': get_date_edited(fname),
			'tags': get_tags(fname),
		}

	# do we have anything files in the database that no longer exist on disk?
	for fname in [x for x in database if not x in fnames]:
		cprint('forgetting %s, as it doesn\'t exist on disk' % fname, 'red')
		del database[fname]

	db_save(database)

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

def initialize_post(fpath):
	global PATH_KB

	now_str = epochToISO8601('now')

	with open(fpath, 'w') as fp:
		fp.write('---\n')
		fp.write('TITLE: Untitled\n')
		fp.write('DATE_CREATED: %s\n' % now_str)
		fp.write('DATE_MODIFIED: %s\n' % now_str)
		fp.write('TAGS: []\n')
		fp.write('---\n')
		fp.write('\n')


