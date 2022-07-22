#!/usr/bin/env python3
#
# command-line BinaryNinja disassembler

import os, sys
import binaryninja

GREEN = '\x1B[32m'
NORMAL = '\x1B[0m'

def print_function_disasm(func):
    for bb in sorted(func.basic_blocks, key=lambda bb: bb.start):
        print('\n'.join(['%08X: %s' % (l.address, l) for l in bb.get_disassembly_text()]))

def usage():
    print('usage: %s <arch> <bytes>' % sys.argv[0])
    print('       %s <fpath> <function>' % sys.argv[0])
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
    print('   eg: %s ./test _foo' % sys.argv[0])
    print('')
    print('architectures:')
    print('\t' + '\n\t'.join(map(lambda x: x.name, list(binaryninja.Architecture))))
    sys.exit(-1)

if __name__ == '__main__':
    if not sys.argv[1:]:
        usage()

    # MODE: disassemble specified function in file
    if os.path.isfile(sys.argv[1]):
        fpath = sys.argv[1]

        with binaryninja.open_view(fpath) as bview:
            if sys.argv[2:]:
                symname = sys.argv[2]
                funcs = bview.get_functions_by_name(symname)
            else:
                funcs = list(bview.functions)

            for (i, func) in enumerate(funcs):
                print(func)
                print_function_disasm(func)
                if i<len(funcs)-1:
                    print()

    # MODE: disassemble bytes given on the command line
    else:
        if not sys.argv[2:]:
            usage()

        arch_name = sys.argv[1]
        byte_list = sys.argv[2:]

        # parse byte arguments
        data = b''.join(list(map(lambda x: int(x,16).to_bytes(1,'big'), byte_list)))

        # disassemble
        arch = binaryninja.Architecture[arch_name]
        toks_len = arch.get_instruction_text(data, 0)
        if not toks_len or toks_len[1]==0:
            print('disassembly failed')
            sys.exit(-1)

        # report
        toks = toks_len[0]
        strs = map(lambda x: x.text, toks)
        print(GREEN, ''.join(strs), NORMAL)

