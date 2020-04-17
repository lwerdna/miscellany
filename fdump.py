#!/usr/bin/env python

import os
import os.path
import sys

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(this_dir)
import taglib

ignore = ['.DS_Store', '.fdump']

NORMAL = '\x1B[0m'

# { '<fname>':
#   { 'tags' : ['<tag1>', '<tag2>', ...],
#     'size' : 123
#   }
#   ...
# }
#   
database = {}

def load_db():
	global database
	
	if not os.path.isfile('.fdump'):
		raise Exception("ERROR: no .fdump found (is this a file dump? use \"init\")")

	with open('.fdump') as fp:
		exec(fp.read(), globals())

def save_db():
	global database

	with open('.fdump', 'w') as fp:
		fp.write('database = {\n')
		for fname in sorted(database):
			fp.write("'%s': { 'tags':[" % fname.replace("'", "\\'"))
			tags = map(lambda x: "'%s'" % x, database[fname]['tags'])
			fp.write(','.join(tags) + "], 'size': %d},\n" % os.path.getsize(fname))
		fp.write('}\n')
		# file object's __exit__() will close()

def refresh():
	global database

	# files that exist, but we don't know about them
	orphans = filter(lambda x: not (x in database or x in ignore), os.listdir('.'))
	# files we know about, but don't exist on disk
	missing = filter(lambda x: not os.path.isfile(x), database)

	# did file get renamed?
	# this is a rare occurence of one or so files, don't worry about efficiency
	renames = []
	for o in orphans:
		for m in missing:
			if os.path.getsize(o) == database[m]['size']:
				renames.append([m, o])

	for [src,dst] in renames:
		database[dst] = database[src]
		del database[src]
		print('%s renamed to %s' % (src, dst))

	# if renames occured, recount orphans and missing
	if renames:
		orphans = filter(lambda x: not (x in database or x in ignore), os.listdir('.'))
		missing = filter(lambda x: not os.path.isfile(x), database)

	# add orphans
	for o in orphans:
		database[o] = {'tags':[], 'size':os.path.getsize(o)}
		print('%s added' % o)

	# forget missing
	for m in missing:
		del database[m]
		print('%s deleted' % m)

def pretty_print(fnames=None):
	global database

	j = max(map(len, database)) + 1

	if not fnames:
		fnames = sorted(database.keys())

	for f in fnames:
		print(f.ljust(j), end='')
		for tag in sorted(database[f]['tags']):
			print('%s%s\033[49;0m' % (taglib.tag_to_color(tag), tag), end='')
		print('')

if __name__ == '__main__':
	if len(sys.argv) < 2 or sys.argv[1]=='ls':
		load_db()
		pretty_print()
	elif sys.argv[1] == 'init':
		database = {}
		refresh()
		save_db()
	elif sys.argv[1] == 'refresh':
		load_db()
		refresh()
		save_db()
	elif sys.argv[1] == 'tags':
		load_db()
		tagCount = {}
		for f in database:
			for t in database[f]['tags']:
				if t in tagCount:
					tagCount[t] += 1
				else:
					tagCount[t] = 1

		for t in tagCount:
			print('%s%s\x1B[0m(%d) ' % (taglib.tag_to_color(t), t, tagCount[t]))
		print('')
	elif sys.argv[1] == 'untagged':
		load_db()
		fnames = filter(lambda x: database[x]['tags']==[], database.keys())
		pretty_print(sorted(fnames))
	else:
		searchTag = sys.argv[1]
		load_db()
		fnames = filter(lambda x: sys.argv[1] in database[x]['tags'], database.keys())
		pretty_print(sorted(fnames))


