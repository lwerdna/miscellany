#!/usr/bin/env python3

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

import os
import argparse
from struct import pack

# some elf defines
(PF_X, PF_W, PF_R) = (1,2,4)
(SHT_NULL, SHT_PROGBITS, SHT_STRTAB) = (0,1,3)
(ET_EXEC) = (2)
(PT_LOAD) = (1)

def build_elf_hdr(class_, data, type_, machine, version, entry, phoff, \
  shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx):
	global fmt_16, fmt_u32, fmt_ptr, sz_ehdr
	hdr = '\x7FELF'
	hdr += chr(class_) # e_ident[EI_CLASS]
	hdr += chr(data) # e_ident[EI_DATA]
	hdr += '\x01\x00\x00' # version, osabi, abiversion
	hdr += '\x00'*7
	assert len(hdr) == 16
	hdr += pack(fmt_u16, type_) 		# e_type = ET_EXEC
	hdr += pack(fmt_u16, machine) 		# e_machine
	hdr += pack(fmt_u32, version) 		# e_version = EV_CURRENT
	hdr += pack(fmt_ptr, entry) 		# e_entry
	hdr += pack(fmt_ptr, phoff) 		# e_phoff
	hdr += pack(fmt_ptr, shoff) 		# e_shoff
	hdr += pack(fmt_u32, flags) 		# e_flags
	hdr += pack(fmt_u16, ehsize) 		# e_ehsize
	hdr += pack(fmt_u16, phentsize) 	# e_phentsize
	hdr += pack(fmt_u16, phnum) 		# e_phnum
	hdr += pack(fmt_u16, shentsize) 	# e_shentsize
	hdr += pack(fmt_u16, shnum) 		# e_shnum
	hdr += pack(fmt_u16, shstrndx) 		# e_shstrndx
	assert len(hdr) == sz_ehdr
	return hdr

def build_phdr(type_, flags, offset, vaddr, paddr, filesz, memsz, \
  align):
	global bits, fmt_u32, fmt_ptr, sz_phdr
	hdr = pack(fmt_u32, type_)			# p_type = PT_LOAD
	if bits == 64:
		hdr += pack(fmt_u32, flags)		# p_flags
	hdr += pack(fmt_ptr, offset)		# p_offset
	hdr += pack(fmt_ptr, vaddr)			# p_vaddr
	hdr += pack(fmt_ptr, paddr)			# p_paddr (physical)
	hdr += pack(fmt_ptr, filesz)		# p_filesz
	hdr += pack(fmt_ptr, memsz)			# p_memsz
	if bits == 32:
		hdr += pack(fmt_ptr, flags)		# p_flags
	hdr += pack(fmt_ptr, align)			# p_align
	assert len(hdr) == sz_phdr
	return hdr

def build_scn_hdr(name, type_, flags, addr, offset, size, link, info, \
  addralign, entsize):
  	global fmt_u32, fmt_ptr, sz_shdr
  	hdr = ''
	# section header
	hdr += pack(fmt_u32, name)			# sh_name
	hdr += pack(fmt_u32, type_)			# sh_type = SHT_PROGBITS
	hdr += pack(fmt_ptr, flags)			# sh_flags = SHF_ALLOC|SHF_EXECINSTR
	hdr += pack(fmt_ptr, addr)			# sh_addr
	hdr += pack(fmt_ptr, offset)		# sh_offset
	hdr += pack(fmt_ptr, size)			# sh_size
	hdr += pack(fmt_u32, link)			# sh_link
	hdr += pack(fmt_u32, info)			# sh_info
	hdr += pack(fmt_ptr, addralign)		# sh_addralign
	hdr += pack(fmt_ptr, entsize)		# sh_entsize
	assert len(hdr) == sz_shdr
	return hdr

parser = argparse.ArgumentParser(description='Wrap a flat binary file in an ELF.')
parser.add_argument('fpath', type=str, help='the flat file to wrap within the ELF')
parser.add_argument('ei_class', type=int, help='0=none, 1=32bit, 2=64bit')
parser.add_argument('ei_data', type=int, help='0=none, 1=L-end, 2=B-end')
# EM_M32, EM_386, etc. from elf-em.h
parser.add_argument('e_machine', type=int, help='3=x32, 40=arm, 62=x64, 183=aarch64')
parser.add_argument('address', type=str, help='address where image loads')
parser.add_argument('entrypoint', type=str, help='address of first instruction')
parser.add_argument('outfile', type=str, help='the output file')
args = parser.parse_args()

# default little-endian pack() formats
(fmt_u16, fmt_u32, fmt_u64) = ('<H', '<I', '<Q')
if args.ei_data == 2:
	(fmt_u16, fmt_u32, fmt_u64) = ('>H', '>I', '>Q')
fmt_ptr = [fmt_u32, fmt_u32, fmt_u64][args.ei_class]
bits = [32,32,64][args.ei_class]
sz_ehdr = [0x34, 0x34, 0x40][args.ei_class]
sz_phdr = [0x20, 0x20, 0x38][args.ei_class]
sz_shdr = [0x28, 0x28, 0x40][args.ei_class]
# .text section from input file
fp = open(args.fpath, 'rb')
scn_text = fp.read()
fp.close()
# .shstrtab section
scn_shstrtab = '\x00.text\x00.shstrtab\x00'

fp = open(args.outfile, 'wb')

# elf header
ehdr = build_elf_hdr(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
o_ehdr = fp.tell()
fp.write(ehdr)

# program header
phdr = build_phdr(0,0,0,0,0,0,0,0)
o_phdr = fp.tell()
fp.write(phdr)

# filler? we need phdr.p_vaddr = phdr.p_offset (mod phdr.p_align)
assert fp.tell() < 0x1000
assert (int(args.address, 16) % 0x1000) == 0
fp.write('\x00' * (0x1000 - fp.tell()))

# text section
o_text = fp.tell()
fp.write(scn_text)

# shstrtab section
o_shstrtab = fp.tell()
fp.write(scn_shstrtab)

# null section header
shdr_null = build_scn_hdr(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)
o_shdr_null = fp.tell()
fp.write(shdr_null)

# text section header
shdr_text = build_scn_hdr(1, SHT_PROGBITS, 6, int(args.address, 16), \
  o_text, len(scn_text), 0, 0, 0, 0)
o_shdr_text = fp.tell()
fp.write(shdr_text)

# shstrtab section headerc
shdr_strs = build_scn_hdr(7, SHT_STRTAB, 0, 0, o_shstrtab, \
  len(scn_shstrtab), 0, 0, 1, 0)
o_shdr_strs = fp.tell()
fp.write(shdr_strs)

# seek back, write real elf header
ehdr = build_elf_hdr(args.ei_class, args.ei_data, ET_EXEC, args.e_machine, 
  1, # version
  int(args.entrypoint, 16), o_phdr,
  o_shdr_null, # offset of first scn hdr
  0, # flags
  sz_ehdr, sz_phdr,
  1, # number of program headers
  sz_shdr,
  3, # number of sections
  2 # index of shstrndx
)
fp.seek(o_ehdr, os.SEEK_SET)
fp.write(ehdr)

phdr = build_phdr(PT_LOAD, PF_X|PF_R, o_text, int(args.address, 16), 0, len(scn_text), \
  len(scn_text), 0x1000)
fp.seek(o_phdr, os.SEEK_SET)
fp.write(phdr)

# done!
fp.close()


