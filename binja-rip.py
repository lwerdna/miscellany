#!/usr/bin/env python

import io
import sys
import struct

import binaryninja

#------------------------------------------------------------------------------
# BINARY NINJA HELPERS
#------------------------------------------------------------------------------
def looks_like_data_seg(seg):
    return not seg.executable and seg.readable

# returns (lowest address, entry address, high address)
def get_func_bounds(func):
    addr_lo = addr_entry = addr_hi = func.basic_blocks[0].start
    for bb in func.basic_blocks:
        addr_lo = min(addr_lo, bb.start)
        addr_hi = max(addr_hi, bb.start)
    return (addr_lo, addr_entry, addr_hi)
    
def get_function_bytes(func, fill=b'\x90'):
    addr_lo, addr_entry, addr_hi = get_func_bounds(func)
    func_len = addr_hi - addr_lo
    fp = io.BytesIO(fill*func_len)
    for bb in func:
        fp.seek(bb.start - addr_lo)
        fp.write(func.view.read(bb.start, bb.end-bb.start))
    fp.seek(0)
    return fp.read()

def get_block_addrs(block):
    result = set()
    addr = block.start
    for _, length in block:
        result.add(addr)
        addr = addr + length
    return result

def get_func_addrs(func):
    result = set()
    for bblock in func:
        result.update(get_block_addrs(bblock))
    return result

# returns the addresses referenced by a function (references TO code or data)
def get_func_references(func):
    result = set()
    bview = func.view
    for addr in get_func_addrs(func):
        for sink in bview.get_code_refs_from(addr): # "code refs" means code -> anything
            result.add(sink)
    return result

# returns the addresses referenced by a function (reference TO data)
def get_references_to_data(func):
    bview = func.view
    return {a for a in get_func_references(func) if looks_like_data_seg(bview.get_segment_at(a))}

def get_length_of_data_at(bview, addr):
    data_vars = bview.data_vars
    assert addr in data_vars

    addrs = sorted(data_vars.keys())
    i = addrs.index(addr)
    if i == len(addrs)-1:
        return bview.get_segment_at(addr).end - addr
    else:
        return addrs[i+1] - addr

def asm_line_transform(x):
    # 'lodsb byte [esi]' -> 'lodsb'
    if x.startswith('lodsb '):
        return 'lodsb'
    # 'stosb byte [edi]' -> 'stosb'
    if x.startswith('stosb '):
        return 'stosb'
    # otherwise
    return x

flavor = 'nasm'
flavor = 'gas'

if __name__ == '__main__':
    fpath, symname = sys.argv[1:]

    bview = binaryninja.open_view(fpath)
    func = bview.get_functions_by_name(symname)[0]

    if flavor == 'nasm':
        print(f'global {func.name}')
    elif flavor == 'gas':
        print(f'.globl {func.name}')
    print('')

    #print('.code')
    if flavor == 'nasm':
        print('section .code')
    elif flavor == 'gas':
        print('.code')
    print('')

    print(f'{func.name}:')
    for block in sorted(func.basic_blocks, key=lambda bb: bb.start):
        if block.start != func.start:
            print(f'loc_{block.start:X}:')

        for toks, length in block:
            texts = []

            for tok in toks:
                if str(tok.type) in ['InstructionTextTokenType.CodeRelativeAddressToken',
                    'InstructionTextTokenType.PossibleAddressToken']:
                    sym = bview.get_symbol_at(tok.value)
                    if sym:
                        texts.append(sym.name)
                    else:
                        seg = bview.get_segment_at(tok.value)
                        if seg and looks_like_data_seg(seg):
                            texts.append(f'data_{tok.value:X}')
                        else:
                            texts.append(f'loc_{tok.value:X}')
                else:
                    texts.append(tok.text)

            line = ''.join(texts)
            line = asm_line_transform(line)
            print('\t' + line)

        #for dtext in block.get_disassembly_text():
        #    print(f'\t{dtext}')

    print('')

    data_addrs = get_references_to_data(func)
    if data_addrs:
        #print('.data')
        if flavor == 'nasm':
            print('section .data')
        elif flavor == 'gas':
            print('.data')

        print('')
        for addr in data_addrs:
            dvar = bview.data_vars[addr]
            if dvar and dvar.name:
                print(f'{dvar.name}:')
            else:
                print(f'data_{addr:X}:')

            length = get_length_of_data_at(bview, addr)
            chunk = bview.read(addr, length)
            while chunk:
                #print('.byte', ' '.join([hex(byte) for byte in chunk[0:8]]))
                print('db', ', '.join([hex(byte) for byte in chunk[0:8]]))
                chunk = chunk[8:]
            print('')

    addr_lo = func.basic_blocks[0].start
    fdata = get_function_bytes(func)

    #data = bincrop.create_elf32(fdata, addr_lo)

    #with open('./ripped-elf32', 'wb') as fp:
    #    fp.write(data)

    #print('done')


