#!/usr/bin/env python

import os
import os.path
import sys

ignore = ['.DS_Store', '.fdump']

# { '<fname>':
#   { 'tags' : ['<tag1>', '<tag2>', ...],
#     'size' : 123
#   }
#   ...
# }
#   
database = {}

def list_to_str(l):
	return '[' + ','.join(l) + ']'

def dict_to_str(d):
	result = '{\n'
	entries = []
	for k in sorted(d):
		entries.append('\'%s\': {\'tags:\': %s' % (k.replace("'", "\\'"), list_to_str(d[k])) + 'len:')
	result += ',\n'.join(entries)
	result += '\n}\n'
	return result

def load_tags():
	global database
	
	if not os.path.isfile('.fdump'):
		raise Exception("ERROR: no .fdump found (is this a file dump? use \"init\")")

	execfile('.fdump', globals())

def save_tags():
	global database

	with open('fdump', 'w') as fp:
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
		print '%s renamed to %s' % (src, dst)

	# if renames occured, recount orphans and missing
	if renames:
		orphans = filter(lambda x: not (x in database or x in ignore), os.listdir('.'))
		missing = filter(lambda x: not os.path.isfile(x), database)

	# add orphans
	for o in orphans:
		database[o] = {'tags':[], 'size':os.path.getsize(o)}
		print '%s added' % o

	# forget missing
	for m in missing:
		del database[m]
		print '%s deleted' % m

def pretty_print():
	global database

	j = max(map(len, database)) + 1

	for f in sorted(database):
		print f.ljust(j),
		print ' '.join(database[f]['tags'])

if __name__ == '__main__':
	if len(sys.argv) < 2 or sys.argv[1]=='ls':
		load_tags()
		pretty_print()
	elif sys.argv[1] == 'init':
		database = {}
		refresh()
		save_tags()
	elif sys.argv[1] == 'refresh':
		load_tags()
		refresh()
		save_tags()
	else:
	# do some stats on tag data
		lenMax = 0
		tagsAll = {}
		for fname in database.keys():
			lenMax = max(lenMax, len(fname))
			for t in database[fname]:
				tagsAll[t] = 1;
			
		print 'all tags: ', ''.join(tagsAll.keys())


