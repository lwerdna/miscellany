#!/usr/bin/env python
# binja type library info utility

import os, sys, re, random
import binaryninja
from binaryninja import typelibrary

if __name__ == '__main__':
	binaryninja._init_plugins()

	fpath = sys.argv[1]
	print('        reading: %s' % fpath)
	
	tl = typelibrary.TypeLibrary.load_from_file(fpath)
	print('           name: %s' % tl.name)
	print('           arch: %s' % tl.arch)
	print('           guid: %s' % tl.guid)
	print('dependency_name: %s' % tl.dependency_name)
	print('alternate_names: %s' % tl.alternate_names)
	print(' platform_names: %s' % tl.platform_names)

	print('  named_objects: %d' % len(tl.named_objects))
	#for (key, val) in tl.named_objects.items():
	#	print('\t"%s" %s' % (str(key), str(val)))

	print('    named_types: %d' % len(tl.named_types))
	#for (key,val) in tl.named_types.items():
	#	print('\t"%s" %s' % (str(key), str(val)))

	#print(repr(tl))
