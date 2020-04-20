#!/usr/bin/env python
#
# command-line BinaryNinja lifter

import sys
import binaryninja
from binaryninja import core
from binaryninja import binaryview
from binaryninja import lowlevelil

RED = '\x1B[31m'
NORMAL = '\x1B[0m'

def traverse_IL(il, indent):
	if isinstance(il, lowlevelil.LowLevelILInstruction):
		print('\t'*indent + il.operation.name)

		for o in il.operands:
			traverse_IL(o, indent+1)

	else:
		print('\t'*indent + str(il))

if __name__ == '__main__':

	if not sys.argv[2:]:
		print('usage: %s <platform> <bytes>' % sys.argv[0])
		print('')
		print('examples:')
		print('   eg: %s linux-armv7 14 d0 4d e2 01 20 a0 e1 00 30 a0 e1 00 c0 a0 e3' % sys.argv[0])
		print('')
		print('platforms:')
		print('\t' + '\n\t'.join(map(str, list(binaryninja.Platform))))

		sys.exit(-1)

	# divide arguments
	platName = sys.argv[1]
	archName = platName.split('-')[1]
	bytesList = sys.argv[2:]

	# parse byte arguments
	data = b''.join(list(map(lambda x: int(x,16).to_bytes(1,'big'), bytesList)))

	plat = binaryninja.Platform[platName]
	bv = binaryview.BinaryView.new(data)
	bv.platform = plat

	bv.add_function(0, plat=plat)

#	print('print all the functions, their basic blocks, and their mc instructions')
#	for func in bv.functions:
#		print(repr(func))
#		for block in func:
#			print("\t{0}".format(block))
#			for insn in block:
#				print("\t\t{0}".format(insn))

	print(RED)
	for func in bv.functions:
		#print(repr(func))
		for block in func.low_level_il:
			#print("\t{0}".format(block))
			for insn in block:
				traverse_IL(insn, 0)
	print(NORMAL)

