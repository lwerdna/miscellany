#!/usr/bin/env python

# CLI interface to kb (knowledge base)

from kblib import *

#------------------------------------------------------------------------------
# misc
#------------------------------------------------------------------------------

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
# output stuff
#------------------------------------------------------------------------------

def db_print(fname):
	database = kblib.db_load()

	fnames = [fname] if fname else sorted(database)
	for fname in fnames:
		print(fname)
		info = database[fname]
		width = max([len(x) for x in info])
		for key in sorted(info):
			print('\t%s: %s' % (key.ljust(width), info[key]))

	print('%d files listed' % len(fnames))

def print_columns(fnames):
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
	database = kblib.db_load()

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

#------------------------------------------------------------------------------
# main
#------------------------------------------------------------------------------

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
		db_save({})
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

