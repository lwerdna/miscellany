#!/usr/bin/env python
#
# command-line BinaryNinja lifter

import sys
import binaryninja
from binaryninja import core
from binaryninja import binaryview
from binaryninja import lowlevelil
from binaryninja.enums import LowLevelILOperation

RED = '\x1B[31m'
NORMAL = '\x1B[0m'

# old style, prints tabs to indicate tree structure
# example:
# LLIL_SET_REG
# 	sp
# 	LLIL_SUB
# 		LLIL_REG
# 			sp
# 		LLIL_CONST
# 			20
def traverse_IL(il, indent):
	if isinstance(il, lowlevelil.LowLevelILInstruction):
		print('\t'*indent + il.operation.name)

		for o in il.operands:
			traverse_IL(o, indent+1)

	else:
		print('\t'*indent + str(il))

# new style
def il2str(il):
	sz_lookup = {1:'.b', 2:'.w', 4:'.d', 8:'.q', 16:'.o'}
	if isinstance(il, lowlevelil.LowLevelILInstruction):
		size_suffix = sz_lookup.get(il.size, '?') if il.size else ''
		# print size-specified IL constants in hex
		if il.operation in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR] and il.size:
			tmp = il.operands[0]
			if tmp < 0: tmp = (1<<(il.size*8))+tmp
			tmp = '0x%X' % tmp if il.size else '%d' % il.size
			return 'LLIL_CONST%s(%s)' % (size_suffix, tmp)
		else:
			return '%s%s(%s)' % (il.operation.name, size_suffix, ','.join([il2str(o) for o in il.operands]))
	elif isinstance(il, list):
		return '[' + ','.join([il2str(x) for x in il]) + ']'
	else:
		return str(il)

if __name__ == '__main__':
	bv = None

	if len(sys.argv)==1:
		print('usage: %s <platform> <bytes>' % sys.argv[0])
		print('       or')
		print('       %s <path>' % sys.argv[0])
		print('')
		print('examples:')
		print('    %s linux-armv7 14 d0 4d e2 01 20 a0 e1 00 30 a0 e1 00 c0 a0 e3' % sys.argv[0])
		print('    %s /path/to/helloworld-elf-a64' % sys.argv[0])
		print('')
		print('platforms:')
		print('\t' + '\n\t'.join(map(str, list(binaryninja.Platform))))

		sys.exit(-1)
	# list of bytes
	elif len(sys.argv)>2:
		platName = sys.argv[1]
		archName = platName.split('-')[1]
		bytesList = sys.argv[2:]

		# parse byte arguments
		data = b''.join(list(map(lambda x: int(x,16).to_bytes(1,'big'), bytesList)))

		plat = binaryninja.Platform[platName]
		bv = binaryview.BinaryView.new(data)
		bv.platform = plat

		bv.add_function(0, plat=plat)
	# path to target
	else:
		fpath = sys.argv[1]
		bv = binaryninja.BinaryViewType.get_view_of_file(fpath)
		bv.update_analysis_and_wait()

	print(RED)
	for func in bv.functions:
		prototype = ''.join(map(lambda x: x.text, func.type_tokens))
		print('')
		print('// %s' % prototype)	
		#print(repr(func))
		for block in func.low_level_il:
			#print("\t{0}".format(block))
			for insn in block:
				#traverse_IL(insn, 0)
				print(il2str(insn))
	print(NORMAL)

