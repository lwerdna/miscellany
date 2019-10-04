#!/usr/bin/env python

import os
import os.path
import sys

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

def tagToColor(tag):
	(fgBlack, fgWhite, fgDefault) = ('\x1B[30m', '\x1B[97m', '\x1B[39m')
	(bgRed, bgGreen, bgOrange, bgBlue, bgPurple, bgCyan, bgLightGray,
	  bgDarkGray, bgLightRed, bgLightGreen, bgYellow, bgLightBlue,
	  bgLightPurple, bgLightCyan, bgWhite, bgDefault) = ('\x1B[41m', '\x1B[42m',
	  '\x1B[43m', '\x1B[44m', '\x1B[45m', '\x1B[46m', '\x1B[47m', '\x1B[100m',
	  '\x1B[101m', '\x1B[102m', '\x1B[103m', '\x1B[104m', '\x1B[105m',
	  '\x1B[106m', '\x1B[107m', '\x1B[49m')

	c1 = fgWhite + bgRed
	c2 = fgWhite + bgGreen
	c3 = fgWhite + bgOrange
	c4 = fgWhite + bgBlue
	c5 = fgWhite + bgPurple
	c6 = fgBlack + bgCyan
	c7 = fgBlack + bgLightGray
	c8 = fgWhite + bgDarkGray
	c9 = fgWhite + bgLightRed
	c10 = fgBlack + bgLightGreen
	c11 = fgBlack + bgYellow
	c12 = fgBlack + bgLightBlue
	c13 = fgBlack + bgLightPurple
	c14 = fgBlack + bgLightCyan
	c15 = fgBlack + bgWhite
	cDefault = fgDefault + bgDefault

	colors = [c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15]

	return colors[sum(map(ord, list(tag))) % len(colors)]

def pretty_print(fnames=None):
	global database

	j = max(map(len, database)) + 1

	if not fnames:
		fnames = sorted(database.keys())

	for f in fnames:
		print(f.ljust(j), end='')
		for tag in sorted(database[f]['tags']):
			print('%s%s\033[49;0m' % (tagToColor(tag), tag), end='')
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
			print('%s%s\x1B[0m(%d) ' % (tagToColor(t), t, tagCount[t]))
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


