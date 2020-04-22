#!/usr/bin/env python3

# given a target file, infer its architecture, read its code, and disassemble it using capstone
#
# $ ./disassemble /path/to/hello.elf
#
# depends on capstone (pip install capstone)

import sys
from struct import pack, unpack

import capstone

# parse the architecture, endianness, and text section from target file
def parse_file(fpath):
	(arch, endian, text_section) = (None, None, None)

	with open(fpath, 'rb') as fp:
		data = fp.read()

	# little endian macho
	if data[0:4] == b'\xCF\xFA\xED\xFE':
		endian = 'little'

		if not data[4:8] == b'\x07\x00\x00\x01': # CPU_TYPE_X86_X64
			raise Exception('only x64 macho files are supported currently')
		arch = 'x64'

		ncmds = unpack('<I', data[16:20])[0]
		#print('ncmds: %d' % ncmds)
		offs = 0x20
		for i in range(ncmds):
			cmd = unpack('<I', data[offs:offs+4])[0]
			cmdsize = unpack('<I', data[offs+4:offs+8])[0]
			#print('cmd %02d: 0x%02X' % (i,cmd))
			if cmd == 0x19: # segment_command_64
				if data[offs+8:offs+16] == b'__TEXT\x00\x00':
					nsects = unpack('<I', data[offs+64:offs+68])[0]
					#print('segment __TEXT nsects: %d' % nsects)

					# advance past command to first section
					o_scn = offs + 0x48
					for i in range(nsects):
						#print('__TEXT section %d: %s' % (i, name))
						# 00: sectname (16)
						# 10: segname (16)
						# 20: addr (8)
						# 28: size (8)
						# 30: offset (4)
						# 34: align (4)
						# 38: reloff (4)
						# 3C: nreloc (4)
						# 40: flags (4)
						# 44: reserved1 (4)
						# 48: reserved2 (4)
						# 4C: reserved3 (4)
						name = data[o_scn+0:o_scn+16]
						if name == b'__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
							(size, offs) = unpack('<QI', data[o_scn+0x28:o_scn+0x34])
							text_section = data[offs:offs+size]
							break

						o_scn += 0x50

			offs += cmdsize

		raise Exception('couldn\'t locate text section in %s' % fpath)

	# ELF
	elif data[0:4] == b'\x7FELF':
		if data[4] == 2: # EI_CLASS 64-bit
			if data[5] == 1: # EI_DATA little endian
				endian = 'little'
			else:
				raise Exception('only little-endian ELF files are supported currently')

			assert data[0x10:0x12] in [b'\x02\x00', b'\x03\x00'] # e_type ET_EXEC or ET_DYN (pie)
			if data[0x12:0x14] != b'\x3E\x00':
				raise Exception('only x64 ELF files are supported currently')
			arch = 'x64'

			# seek sections
			(e_shoff,_,_,_,_,e_shentsize,e_shnum,e_shstrndx) = unpack('<QIHHHHHH', data[0x28:0x40])

			# get string table sections
			offs = e_shoff + e_shstrndx*e_shentsize
			(_, sh_type, _, _, sh_offset, sh_size) = unpack('<IIQQQQ', data[offs:offs+0x28])
			#print('offs: ', offs)
			#print('sh_type: ', sh_type)
			assert sh_type == 3 # (STRTAB)
			strtab = data[sh_offset:sh_offset+sh_size]

			# loop over sections until name '.
			offs = e_shoff
			for i in range(e_shnum):
				(sh_name, _, _, _, sh_offset, sh_size) = unpack('<IIQQQQ', data[offs:offs+40])

				if strtab[sh_name:].startswith(b'.text\x00'):
					text_section = data[sh_offset:sh_offset + sh_size]
					break

				offs += e_shentsize
	else:
		(arch, endian, text_section) = ('x64', 'little', data)

	return (arch, endian, text_section)

md = None
def disassemble(data):
	global md
	gen = md.disasm(data, 0)

	offset = 0
	for i in gen:
		addrstr = '%08X' % i.address
		bytestr = ' '.join(['%02X'%x for x in data[offset:offset+i.size]])
		asmstr = i.mnemonic + ' ' + i.op_str
		line = '%s: %s %s' % (addrstr, bytestr.ljust(48), asmstr)
		print(line)
		offset += i.size	

if __name__ == '__main__':
	fpath = sys.argv[1]
	(arch, endian, code) = parse_file(fpath)
	
	if arch == 'x64':
		md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
	
	assert md
	disassemble(code)

