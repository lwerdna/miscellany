#!/usr/bin/env python

import os
import re
import sys
import time
import tempfile
import subprocess

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(this_dir)
import cplib

def sanitize_filename(name: str, replacement: str = "_") -> str:
    # Whitelist: letters, digits, dash, underscore, dot, and space
    safe = re.sub(r'[^a-zA-Z0-9_\-]', replacement, name)
    # Collapse multiple replacements (like "___") into a single one
    safe = re.sub(rf"{re.escape(replacement)}+", replacement, safe)
    # Strip leading/trailing spaces or replacement chars
    safe = safe.strip(" ._-")
    return safe

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('supply entry number to edit and the destination')

    index = int(sys.argv[1])
    dest = sys.argv[2]
    assert dest in ['tech', 'thoughts', 'chess']
    wikidir = 'wiki_'+dest

    entries = cplib.get_entries()
    entry = entries[index]

    sanitized = sanitize_filename(entry['lines'][0])
    fname = entry['date'] + ' ' + sanitized + '.md'
    fpath = os.path.join('..', wikidir, fname)

    start, end = entry['start'], entry['end']

    #print(f'will slice lines [{start}, {end}] (1-indexed)')

    cppath = os.path.abspath('Commonplace.md')
    cpdir, _ = os.path.split(cppath)
    print(f'cppath: {cppath} (directory: {cpdir})')
    with open(cppath) as fp:
        lines = fp.readlines()

    before = lines[0:start]
    after = lines[end+1:]

    slice_ = lines[start:end+1]
    assert slice_[0].startswith('{')
    assert slice_[-1].startswith('}')

    # write the new markdown file
    print(f'writing: {fpath}')
    with open(fpath, 'w') as fp:
        #fp.write(''.join(slice_[1:-1])) # discluding the {'s and }'s
        fp.write(''.join(slice_))

    # delete the slice from the old markdown file
    with open('Commonplace.md', 'w') as fp:
        fp.write(''.join(before))
        fp.write(''.join(after))
