#!/usr/bin/env python3
#
# command-line BinaryNinja disassembler

import sys
import binaryninja

GREEN = '\x1B[32m'
NORMAL = '\x1B[0m'

if not sys.argv[2:]:
	print('usage: %s <arch> <bytes>' % sys.argv[0])
	print('examples:')
	print('   eg: %s aarch64  ff 43 00 d1' % sys.argv[0])
	print('   eg: %s armv7    14 d0 4d e2' % sys.argv[0])
	print('   eg: %s armv7eb  14 d0 4d e2' % sys.argv[0])
	print('   eg: %s mips32   27 bd ff f0' % sys.argv[0])
	print('   eg: %s mipsel32 f0 ff bd 27' % sys.argv[0])
	print('   eg: %s ppc      93 e1 ff fc' % sys.argv[0])
	print('   eg: %s ppc_le   fc ff e1 93' % sys.argv[0])
	print('   eg: %s thumb2   85 b0' % sys.argv[0])
	print('   eg: %s thumb2eb b0 85' % sys.argv[0])
	print('   eg: %s x86      55' % sys.argv[0])
	print('   eg: %s x86_64   55' % sys.argv[0])
	print('')
	print('architectures:')
	print('\t' + '\n\t'.join(map(lambda x: x.name, list(binaryninja.Architecture))))
	sys.exit(-1)

# divide arguments
archName = sys.argv[1]
bytesList = sys.argv[2:]

# parse byte arguments
data = b''.join(list(map(lambda x: int(x,16).to_bytes(1,'big'), bytesList)))

# disassemble
arch = binaryninja.Architecture[archName]
toksAndLen = arch.get_instruction_text(data, 0)
if not toksAndLen or toksAndLen[1]==0:
	print('disassembly failed')
	sys.exit(-1)

# report
toks = toksAndLen[0]
strs = map(lambda x: x.text, toks)
print(GREEN, ''.join(strs), NORMAL)

