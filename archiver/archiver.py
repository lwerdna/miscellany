#!/usr/bin/env python

import os
import re
import sys
import pickle
import shutil
import hashlib
import tempfile
import subprocess

# list of: descr(str) fname(str) tags(list(str)) md5(str) size(int)
database = []

def dbRead():
	global database, fileSizes, hashes
	database = pickle.load(open('archive.p', 'rb'))

def dbWrite():
	global database
	pickle.dump(database, open('archive.p', 'wb'))

def dbDump(db=database):
	global database

	print '{:^4} {:^32} {:^16} {:^8} {}'.format('id', 'descr', 'fname', 'size', 'tags')
	print '{:-^4} {:-^32} {:-^16} {:-^8} ----'.format('','','','')

	for (i,entry) in enumerate(db):

		(descr,fname,size,tags) = \
			(entry['descr'], entry['fname'], entry['size'], entry['tags'])
	
		if len(fname) > 16:
			fname = fname[:11] + '..' + fname[-3:]
	
		tags = ','.join(tags)
	
		print '{:04d} {:<32.32} {:>16.16} {:>8} {}'.format(i,descr,fname,size,tags)

# test if file is in database
# exists -> return entry (database row)
# doesnt -> return False
def dbTestFileExist(path):
	global database

	# quickest test: filesize
	size = os.path.getsize(path)
	matches = filter(lambda entry: size == entry['size'], database)
	if not matches:
		return False
	
	# slower test: hash
	md5 = md5File(path)
	matches = filter(lambda entry: md5 == entry['md5'], database)
	if not matches:
		return False

	assert(len(matches)==1)
	return matches[0]

def md5File(path):
	ctx = hashlib.md5()
	with open(path, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			ctx.update(chunk)
	return ctx.hexdigest()

def askUserFileInfo(entry):
	if not entry:
		entry = {'descr':'', 'fname':'', 'tags':[], 'md5':'', 'size':0}

	body = 'descr: %s\n' % entry['descr']
	body += 'fname: %s\n' % entry['fname']
	body += 'tags: %s\n' % (''.join(entry['tags']))
	body += 'md5: %s\n' % entry['md5']
	body += 'size: %d\n' % entry['size']

	(tmp_handle, tmp_name) = tempfile.mkstemp()
	tmp_obj = os.fdopen(tmp_handle, 'w')
	tmp_obj.write(body)
	tmp_obj.close()

	# edit
	subprocess.call(["vim", '-f', tmp_name])

	# now open, encode, encrypt
	fp = open(tmp_name)
	lines = fp.readlines()
	fp.close()
	m = re.match(r'^descr: (.*)$', lines[0])
	descr = m.group(1)
	m = re.match(r'^fname: (.*)$', lines[1])
	fname = m.group(1)
	m = re.match(r'^tags: (.*)$', lines[2])
	tags = m.group(1).split(',')
	m = re.match(r'^md5: (.*)$', lines[3])
	md5 = m.group(1)
	m = re.match(r'^size: (.*)$', lines[4])
	size = int(m.group(1))

	return {'descr':descr, 'fname':fname, 'tags':tags, 'md5':md5, 'size':size}

if __name__ == '__main__':
	dbRead()

	if not sys.argv[1:]:
		dbDump(database)

	elif sys.argv[1]=='addfast':
		for path in sys.argv[2:]:
			print "adding: %s" % path
			entry = dbTestFileExist(path)
			if entry:
				print "exists already (%s)" % entry['fname']
			else:
				entry = {'descr':'', 'fname':os.path.basename(path), 'tags':[], 'md5':md5File(path), 'size':os.path.getsize(path)}
				database.append(entry)
				shutil.copyfile(path, os.path.normpath(os.path.join(os.getcwd(), os.path.basename(path))))

		dbWrite()

	elif sys.argv[1]=='edit':
		idx = int(sys.argv[2])
		entry = askUserFileInfo(database[idx])
		database[idx] = entry
		print "one record changed"
		dbDump([entry])
		dbWrite()
			
