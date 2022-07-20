#!/usr/bin/env python

# get the control flow graph (CFG) of a function in DOT

def block_id(bb):
    return 'b%d' % bb.index

def block_label(bb):
    lines = []
    addr = bb.start
    for (toks, length) in bb:
        lines.append('%08X: %s' % (addr, ''.join([t.text for t in toks])))
        addr += length
    return '\\l'.join(lines)

def func_to_dot(func):
    print('digraph G {')
    print('\t// graph settings')
    print('\tnode [shape="rectangle"];')

    # block identifiers and labels
    print('\t// nodes')
    for block in func.basic_blocks:
        label = block_label(block).replace('"', '&quot;')
        print('\t%s[label="%s"];' % (block_id(block), label))

    # block identifier to block identifier
    print('\t// edges')
    for src in func.basic_blocks:
        for edge in src.outgoing_edges:
            dst = edge.target
            print('\t%s -> %s;' % (block_id(src), block_id(dst)))

    print('}') 

if __name__ == '__main__':
    import sys
    if not sys.argv[1:]:
        print(f'examples:')
        print(f'  {sys.argv[0]} /bin/ls _start')
        print(f'  {sys.argv[0]} /bin/ls sub_100003a46')
        print(f'  {sys.argv[0]} ~/fdumps/filesamples/hello-linux-x64.elf __libc_csu_init')
        sys.exit(-1)

    import binaryninja

    fpath = sys.argv[1]
    sym_name = sys.argv[2].lower()

    print(f'// opening: {fpath}')
    with binaryninja.open_view(fpath) as bview:
        print(f'// looking up symbol: {sym_name}')
        functions = [f for f in bview.functions if f.name.lower() == sym_name.lower()]
        if not functions:
            raise Exception(f'symbol {sym_name} not in function list')
        if len(functions) > 1:
            print(f'symbol {sym_name} is ambiguous (appearing multiple times in function list), taking first...')
        function = functions[0]

        func_to_dot(function)

