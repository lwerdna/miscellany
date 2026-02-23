#!/usr/bin/env python

import os
import sys
import time
import tempfile
import subprocess

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(this_dir)
import cplib

def wait_for_save(fpath):
    t0 = os.path.getmtime(fpath)
    print(f'initial modification time: {t0}')

    while True:
        time.sleep(1)
        t1 = os.path.getmtime(fpath)
        if t1 == t0:
            continue

        break

    print('done')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('supply entry number to edit')

    index = int(sys.argv[1])

    entries = cplib.get_entries()
    entry = entries[index]

    start, end = entry['start'], entry['end']

    print(f'will slice lines [{start}, {end}] (1-indexed)')

    cppath = os.path.abspath('Commonplace.md')
    cpdir, _ = os.path.split(cppath)
    print(f'cppath: {cppath} (directory: {cpdir})')
    with open(cppath) as fp:
        lines = fp.readlines()

    slice_ = lines[start:end+1]
    assert slice_[0].startswith('{')
    assert slice_[-1].startswith('}')

    #(tmp_handle, tmp_name) = tempfile.mkstemp(dir=cpdir, suffix='.md')
    #print("writing temporary contents to %s" % tmp_name)
    #tmp_obj = os.fdopen(tmp_handle, 'w')
    #tmp_obj.write('\n'.join(slice_))
    #tmp_obj.close()
    tpath = os.path.join(cpdir, 'slice.md')
    with open(tpath, 'w') as fp:
        fp.write(''.join(slice_[1:-1]))
    cmds = ['open', '-a', 'Typora', tpath]
    print(f'invoking: {" ".join(cmds)}')
    subprocess.call(cmds)
    print('waiting for changes')
    wait_for_save(tpath)
    print('applying changes')

    with open(tpath) as fp:
        lines_new = fp.readlines()
    with open(cppath) as fp:
        lines = fp.readlines()
        lines = lines[0:start+1] + lines_new + lines[end:]
    with open(cppath, 'w') as fp:
        fp.write(''.join(lines))

