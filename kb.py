#!/usr/bin/env python

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
#				'title': title (string),
#				'mtime': file modification time (float),
#				'date_created': creation time (float),
#				'date_edited': edit time (float),
#				'tags': tags (list),
#			}
# }

# central place to decide how to edit a file (vim, gvim, macvim, typora, etc.)
def edit_file(fpath, method='macvim'):
	if method == 'macvim':
		os.system('open -a macvim %s' % fpath)
	elif method == 'typora':
		os.system('open -a typora %s' % fpath)
	elif method == 'gvim':
		os.system('gvim %s +' % fpath)
	elif method == 'vim':
		os.system('vim %s +' % fpath)

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
	code = code.replace(',', '')
	return code.split(' ')

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

	# else, the edit date is the created data
	return get_date_created(fname)

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

def db_update(force=False):
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
			if mtime_db >= mtime_fs and not force: # database is current
				continue
			cprint('updating %s' % fname, 'yellow')

		database[fname] = {
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

	db_save()

def db_print(fname):
	global database
	db_load()

	fnames = [fname] if fname else sorted(database)
	for fname in fnames:
		print(fname)
		print('\t        title: %s' % database[fname]['title'])
		print('\t        mtime: %s' % epochToISO8601(database[fname]['mtime']))
		print('\t date_created: %s' % epochToISO8601(database[fname]['date_created']))
		print('\t  date_edited: %s' % epochToISO8601(database[fname]['date_edited']))
		print('\t         tags: %s' % database[fname]['tags'])

	print('%d files listed' % len(fnames))

#------------------------------------------------------------------------------
# output stuff
#------------------------------------------------------------------------------

def print_columns(fnames):
	global database

	column_width = 32
	column_quantity = os.get_terminal_size().columns // column_width
	column_quantity = max(column_quantity, 1)

	#fnames = sorted(fnames, key=lambda x: database[x]['date_edited'])
	fnames = sorted(fnames)

	while fnames:
		line = ''
		for fname in fnames[0:column_quantity]:
			tmp = fname.ljust(column_width)
			line += tmp
			# if this filename breaks the look, go to new line
			if len(tmp) > column_width:
				break

		print(line)
		fnames = fnames[column_quantity:]

def perform_ls(limit, tags=[]):
	global database
	db_load()

	# if tags are specified, filter entries that have tags
	if tags:
		tags = [x[1:] if x.startswith('#') else x for x in tags]

		dbtemp = {}
		for fname in database:
			if set(database[fname]['tags']).isdisjoint(tags):
				continue
			dbtemp[fname] = database[fname]
		database = dbtemp

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
			print_columns(collection)
		seen.update(collection)
		if len(seen) > limit:
			break

def gen_blog():
	import markdown

	html_css = '''
      table {
        border: 1px solid black;
      }
      td, th {
        border: 1px solid black;
        padding: 2px;
      }
      code {
        background-color: #E0E0E0;
      }
      h1,h2,h3,h4 {
        margin-bottom: 0;
      }
      pre {
        background-color: #E0E0E0;
        padding: 4px;
      }
      blockquote {
        background-color: pink;
      }
'''

	html_header = '''
	<!DOCTYPE html>
	<html>
	  <head>
	    <meta charset="utf-8">
	    <title>%s</title>
	    <style>
	''' + html_css + '''
	    </style>
	  </head>
	  <body>
'''

	html_footer = '''
	  </body>
	</html>
'''

	global database
	db_load()

#	<fname>: {
#				'mtime': file modification time (float),
#				'date_created': creation time (float),
#				'date_edited': edit time (float),
#				'tags': tags (list),
#			}
	print(html_header % 'My Blog')

	for fname in sorted(database, key=lambda fname: database[fname]['date_created']):
		if not 'publish' in database[fname]['tags']:
			continue

		title = database[fname].get('title', 'Untitled')
		date_c = epochToISO8601(database[fname]['date_created'])
		date_m = epochToISO8601(database[fname]['date_edited'])
		tags = [t for t in database[fname]['tags'] if t != 'publish']

		print('<h3>%s</h3>' % title)
		print('created: %s<br>' % date_c)
		if date_m and date_m != date_c:
			print('updated: %s<br>' % date_m)
		tag_links = ['<a href=tags_%s.html>#%s</a>' % (tag, tag) for tag in tags]
		if tag_links:
			print('tags: ' + ' '.join(tag_links), end='')

		with open(fname, 'r') as fp:
			lines = fp.readlines()

		# eat front matter
		if lines[0].startswith('---'):
			i = 1
			while not lines[i].startswith('---'):
				i += 1
			lines = lines[i+1:]

		if fname.endswith('.txt'):
			print('<pre>')
			print(''.join(lines))
			print('</pre>')

		elif fname.endswith('.md'):
			html = markdown.markdown(''.join(lines), extensions=['tables', 'fenced_code', 'toc'])
			print(html)

	print(html_footer)

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

if __name__ == '__main__':
	cmd = ''
	if sys.argv[1:]:
		cmd = sys.argv[1]

	arg0 = None
	if sys.argv[2:]:
		arg0 = sys.argv[2]

	if cmd == 'blog':
		gen_blog()
	elif cmd == 'update':
		db_update()
	elif cmd == 'forceupdate':
		db_update(True)
	elif cmd == 'forget':
		database = {}
		db_save()
	elif cmd == 'dump':
		fname = None
		if sys.argv[2:]:
			fname = sys.argv[2]
		db_print(fname)
	elif cmd == 'ls':
		perform_ls(32)
	elif cmd == 'lsall':
		perform_ls(1000000)
	elif cmd == 'rfm':
		front_matter = read_front_matter(arg0)
		print(front_matter)
	elif cmd == 'rm':
		src = arg0
		dst = os.path.join('/tmp', src)
		if not os.path.exists(src):
			raise Exception('cannot delete %s, doesn\'t exist' % src)
		print('deleting %s, backup copied to %s' % (src, dst))
		shutil.copyfile(src, dst)
		os.unlink(src)
	elif cmd in ['tags', 'tag', 'lstag', 'lstags', 'lst']:
		perform_ls(1000000, sys.argv[2:])

	# is it a tag? (probably will have to escape this on your shell, like: `kb \#book`)
	elif cmd.startswith('#'):
		perform_ls(1000000, sys.argv[1:])

	# assume it's a filename
	else:
		fname = cmd
		if not (fname.endswith('.md') or fname.endswith('.txt')):
			fname = fname + '.md'
		if os.path.exists(fname):
			print('opening', fname)
		else:
			print('creating', fname)
			initialize_post(fname)

		edit_file(fname)

