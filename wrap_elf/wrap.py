#!/usr/bin/env python

# wrap a flat file as the .text section of an ELF file
# resulting file is simple:
# ------------------------
# ELF header
# ------------------------
# program header
# ------------------------
# .text section
# .shstrtab section
# ------------------------
# NULL section header
# .text section header
# .shstrtab section header
# ------------------------

import argparse
from struct import pack

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3

parser = argparse.ArgumentParser(description='Wrap a flat binary file in an ELF.')
parser.add_argument('fpath', type=str, help='the flat file to wrap within the ELF')
parser.add_argument('ei_class', type=int, help='0=none, 1=32bit, 2=64bit')
parser.add_argument('ei_data', type=int, help='0=none, 1=L-end, 2=B-end')
# EM_M32, EM_386, etc. from elf-em.h
parser.add_argument('e_machine', type=int, help='3=x32, 40=arm, 62=x64, 183=aarch64')
parser.add_argument('address', type=int, help='address where image loads')
parser.add_argument('entrypoint', type=int, help='address of first instruction')
parser.add_argument('outfile', type=str, help='the output file')
args = parser.parse_args()

print 'fpath: %s' % args.fpath
print 'number: %d' % args.number
#print 'machine is: %d' % args.machine

# default little-endian pack() formats
(fmt_u16, fmt_u32, fmt_u64) = ('<H', '<I', '<Q')
if args.ei_data == 2:
	(fmt_u16, fmt_u32, fmt_u64) = ('>H', '>I', '>Q')
fmt_ptr = [fmt_u32, fmt_u32, fmt_u64][args.ei_class]
bits = [32,32,64][args.ei_class]
sz_elfhdr = [0x34, 0x34, 0x40][args.ei_class]
sz_phdr = [0x20, 0x20, 0x38][args.ei_class]
sz_scnhdr = [0x28, 0x28, 0x40][args.ei_class]

def build_elf_hdr(class_, data, type_, machine, version, entry, phoff, \
  shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx):
	# build elf header
	elf_hdr = '\x7FELF'
	elf_hdr += chr(args.ei_class) # e_ident[EI_CLASS]
	elf_hdr += chr(args.ei_data) # e_ident[EI_DATA]
	elf_hdr += '\x01\x00\x00' # version, osabi, abiversion
	elf_hdr += '\x00'*7
	assert len(elf_hdr) == 16
	elf_hdr += pack(fmt_u16, 2) 			# e_type = ET_EXEC
	elf_hdr += pack(fmt_u16, args.e_machine) # e_machine
	elf_hdr += pack(fmt_u32, 1) 			# e_version = EV_CURRENT
	elf_hdr += pack(fmt_ptr, 0) 			# e_entry
	elf_hdr += pack(fmt_ptr, sz_elfhdr) 	# e_phoff
	elf_hdr += pack(fmt_ptr, TODO) 			# e_shoff
	elf_hdr += pack(fmt_u32, e_flags) 		# e_flags
	elf_hdr += pack(fmt_u16, e_ehsize) 		# e_ehsize
	elf_hdr += pack(fmt_u16, sz_phdr) 		# e_phentsize
	elf_hdr += pack(fmt_u16, 1) 			# e_phnum
	elf_hdr += pack(fmt_u16, sz_scnhdr) 	# e_shentsize
	elf_hdr += pack(fmt_u16, 1) 			# e_shnum
	elf_hdr += pack(fmt_u16, 0) 			# e_shstrndx
	assert len(elf_hdr) == sz_elfhdr

def build_phdr(type_, flags, offset, vaddr, paddr, filesz, memsz, \
  flags, align):
  	hdr = ''
	# build program header
	hdr += pack(fmt_u32, 1)					# p_type = PT_LOAD
	if bits == 64:
		hdr += pack(fmt_u32, 0)				# p_flags
	hdr += pack(fmt_ptr, 0)					# p_offset
	hdr += pack(fmt_ptr, 0)					# p_vaddr
	hdr += pack(fmt_ptr, 0)					# p_paddr (physical)
	hdr += pack(fmt_ptr, 0)					# p_filesz
	hdr += pack(fmt_ptr, 0)					# p_memsz
	#hdr += pack(fmt_ptr, 0)				# p_flags
	hdr += pack(fmt_ptr, 0)					# p_align
	assert len(hdr) == sz_phdr

def build_scn_hdr(name, type_, flags, addr, offset, size, link, info, \
  addralign, entsize):
  	hdr = ''
	# section header
	hdr += pack(fmt_u32, name)				# sh_name
	hdr += pack(fmt_u32, type_)				# sh_type = SHT_PROGBITS
	hdr += pack(fmt_ptr, flags)				# sh_flags = SHF_ALLOC|SHF_EXECINSTR
	hdr += pack(fmt_u32, addr)				# sh_addr
	hdr += pack(fmt_u32, offset)			# sh_offset
	hdr += pack(fmt_u32, size)				# sh_size
	hdr += pack(fmt_u32, link)				# sh_link
	hdr += pack(fmt_u32, info)				# sh_info
	hdr += pack(fmt_u32, addralign)			# sh_addralign
	hdr += pack(fmt_u32, entsize)			# sh_entsize
	return hdr

scn_strs = '\x00.text\x00.shstrtab\x00'
ehdr = build_elf_hdr(args.ei_class, args.ei_data, ET_EXEC, args.e_machine, \
  1, 0, sz_elfhdr, TODO, e_flags, e_ehsize, sz_phdr, 1, sz_scnhdr, 1, 0)
phdr = build_phdr(PT_LOAD, flags, offset, vaddr, paddr, filesz, memsz, \
  flags, align)
shdr_null = build_scn_hdr(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)
shdr_text = build_scn_hdr(1, SHT_PROGBITS, 6, addr, offs, size, 0, 0x1000, 0)
shdr_strs = build_scn_hdr(7, SHT_STRTAB, 0, 0, OFFSET, SZ)

fp = open(args.outfile, 'wb')
fp.write(elf_hdr)
fp.write(phdr)
fp.write(
assert len(scn_hdr) == sz_scnhdr




