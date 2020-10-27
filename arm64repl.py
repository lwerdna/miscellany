#!/usr/bin/env python

# an assembly REPL for x86

import re
import readline

from unicorn import *
from unicorn.arm64_const import *

from keystone import *

rname_to_unicorn = {
	'x0': UC_ARM64_REG_X0, 'x1': UC_ARM64_REG_X1, 'x2': UC_ARM64_REG_X2, 'x3': UC_ARM64_REG_X3,
	'x4': UC_ARM64_REG_X4, 'x5': UC_ARM64_REG_X5, 'x6': UC_ARM64_REG_X6, 'x7': UC_ARM64_REG_X7,
	'x8': UC_ARM64_REG_X8, 'x9': UC_ARM64_REG_X9, 'x10': UC_ARM64_REG_X10, 'x11': UC_ARM64_REG_X11,
	'x12': UC_ARM64_REG_X12, 'x13': UC_ARM64_REG_X13, 'x14': UC_ARM64_REG_X14, 'x15': UC_ARM64_REG_X15,
	'x16': UC_ARM64_REG_X16, 'x17': UC_ARM64_REG_X17, 'x18': UC_ARM64_REG_X18, 'x19': UC_ARM64_REG_X19,
	'x20': UC_ARM64_REG_X20, 'x21': UC_ARM64_REG_X21, 'x22': UC_ARM64_REG_X22, 'x23': UC_ARM64_REG_X23,
	'x24': UC_ARM64_REG_X24, 'x25': UC_ARM64_REG_X25, 'x26': UC_ARM64_REG_X26, 'x27': UC_ARM64_REG_X27,
	'x28': UC_ARM64_REG_X28, 'x29': UC_ARM64_REG_X29, 'x30': UC_ARM64_REG_X30,
	'fp': UC_ARM64_REG_FP, # or UC_ARM64_REG_X29
	'lr': UC_ARM64_REG_LR, # or UC_ARM64_REG_X30
	'nzcv': UC_ARM64_REG_NZCV,
	'pc': UC_ARM64_REG_PC,
	'sp': UC_ARM64_REG_SP,
}

# set up emulator, assembler
ADDRESS = 0x1000000
ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)	
mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
mu.mem_map(ADDRESS, 4096)

while 1:
	cmd = input('> ')

	isasm = True

	try:
		m = re.match(r'.regset (.*) (.*)', cmd)
		if m:
			(rname, rval) = m.group(1, 2)
			mu.reg_write(rname_to_unicorn[rname], int(rval, 16))
			isasm = False
	
		if isasm and cmd:
			encoding, count = ks.asm(cmd)
			data = b''.join([x.to_bytes(1,'big') for x in encoding])
			print('assembles to:', data.hex())
			mu.mem_write(ADDRESS, data)
			mu.emu_start(ADDRESS, ADDRESS + len(encoding))

	except KsError as e:
		print('keystone error:', e)

	except UcError as e:
		print('unicorn error:', e)

	# show context
	print(' x0=%016X  x1=%016X  x2=%016X  x3=%016X' % \
		(mu.reg_read(UC_ARM64_REG_X0), mu.reg_read(UC_ARM64_REG_X1), \
		mu.reg_read(UC_ARM64_REG_X2), mu.reg_read(UC_ARM64_REG_X3)))
	print(' x4=%016X  x5=%016X  x6=%016X  x7=%016X' % \
		(mu.reg_read(UC_ARM64_REG_X4), mu.reg_read(UC_ARM64_REG_X5), \
		mu.reg_read(UC_ARM64_REG_X6), mu.reg_read(UC_ARM64_REG_X7)))
	print(' x8=%016X  x9=%016X x10=%016X x11=%016X' % \
		(mu.reg_read(UC_ARM64_REG_X8), mu.reg_read(UC_ARM64_REG_X9), \
		mu.reg_read(UC_ARM64_REG_X10), mu.reg_read(UC_ARM64_REG_X11)))
	print('x12=%016X x13=%016X x14=%016X x15=%016X' % \
		(mu.reg_read(UC_ARM64_REG_X12), mu.reg_read(UC_ARM64_REG_X13), \
		mu.reg_read(UC_ARM64_REG_X14), mu.reg_read(UC_ARM64_REG_X15)))
	print('x16=%016X x17=%016X x18=%016X x19=%016X' % \
		(mu.reg_read(UC_ARM64_REG_X16), mu.reg_read(UC_ARM64_REG_X17), \
		mu.reg_read(UC_ARM64_REG_X18), mu.reg_read(UC_ARM64_REG_X19)))
	print('x21=%016X x22=%016X x23=%016X x24=%016X' % \
		(mu.reg_read(UC_ARM64_REG_X21), mu.reg_read(UC_ARM64_REG_X22), \
		mu.reg_read(UC_ARM64_REG_X23), mu.reg_read(UC_ARM64_REG_X24)))
	print('x25=%016X x26=%016X x27=%016X x28=%016X' % \
		(mu.reg_read(UC_ARM64_REG_X25), mu.reg_read(UC_ARM64_REG_X26), \
		mu.reg_read(UC_ARM64_REG_X27), mu.reg_read(UC_ARM64_REG_X28)))
	print(' fp=%016X  lr=%016X' % 
		(mu.reg_read(UC_ARM64_REG_FP), mu.reg_read(UC_ARM64_REG_LR)))
	print(' pc=%016X  nzcv=%016X' % 
		(mu.reg_read(UC_ARM64_REG_PC), mu.reg_read(UC_ARM64_REG_NZCV)))
