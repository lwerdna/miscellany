#!/usr/bin/env python

# get the control flow graph (CFG) of a function in mermaid diagram

def block_id(bb):
    return 'b%d' % bb.index

def block_label(bb):
    lines = []
    addr = bb.start
    for (toks, length) in bb:
        lines.append('%08X: %s' % (addr, ''.join([t.text for t in toks])))
        addr += length
    return '<br>'.join(lines)

def func_to_mermaid(func):
    result = ['graph TD']

    # block identifiers and labels
    for block in func.basic_blocks:
        label = block_label(block).replace('"', '&quot;')
        result.append('\t%s["%s"]' % (block_id(block), label))

    # block identifier to block identifier
    for src in func.basic_blocks:
        for edge in src.outgoing_edges:
            dst = edge.target
            result.append('\t%s --> %s' % (block_id(src), block_id(dst)))

    return '\n'.join(result)

if __name__ == '__main__':
    import sys
    if not sys.argv[1:]:
        print(f'examples:')
        print(f'  {sys.argv[0]} /bin/ls _start')
        print(f'  {sys.argv[0]} /bin/ls sub_100003a46')
        sys.exit(-1)

    import binaryninja

    fpath = sys.argv[1]
    sym_name = sys.argv[2].lower()

    print(f'opening: {fpath}')
    with binaryninja.open_view(fpath) as bview:
        print(f'looking up symbol: {sym_name}')
        functions = [f for f in bview.functions if f.name.lower() == sym_name.lower()]
        if not functions:
            raise Exception(f'symbol {sym_name} not in function list')
        if len(functions) > 1:
            print(f'symbol {sym_name} is ambiguous (appearing multiple times in function list), taking first...')
        function = functions[0]

        print('```mermaid')
        print(func_to_mermaid(function))
        print('```') 

