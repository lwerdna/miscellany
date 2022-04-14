#!/usr/bin/env python
#
# command-line VEX lifter

import sys
import angr

RED = '\x1B[31m'
NORMAL = '\x1B[0m'

def usage():
	print('usage: %s <platform> <bytes>' % sys.argv[0])
	print('')
	print('examples:')
	print('   eg: %s ARM 14 d0 4d e2 01 20 a0 e1 00 30 a0 e1 00 c0 a0 e3' % sys.argv[0])
	print('   eg: %s ARM64 64 41 20 1e' % sys.argv[0])
	print('   eg: %s AMD64 90 90 90 90' % sys.argv[0])
	print('')
	print('platforms:')
	print('\tX86, AMD64, ARM, ARM64')

if __name__ == '__main__':
	if not sys.argv[2:]:
		usage()
		sys.exit(-1)

	# divide arguments
	platName = sys.argv[1].lower()
	if not (platName in ['x86', 'amd64', 'arm', 'arm64']):
		usage()
		sys.exit(-1)

	# bytes list
	bytesList = sys.argv[2:]
	data = b''.join(list(map(lambda x: int(x,16).to_bytes(1,'big'), bytesList)))

	proj = angr.load_shellcode(data, arch=platName.lower())
	# print disassembly
	block0 = proj.factory.block(0)
	block0.pp()
	# print IL
	vex = proj.factory.block(0).vex
	vex.pp()

	#print(RED)
	#print(NORMAL)

