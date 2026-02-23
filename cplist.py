#!/usr/bin/env python

import os, sys, re, pprint

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(this_dir)
import cplib

if __name__ == '__main__':
    tag = None
    for arg in sys.argv[1:]:
        if arg.startswith('#'):
            tag = arg
        elif os.path.exists(arg):
            infile = arg

    if tag != None:
        print(f'filtering tag: {tag}')

    entries = cplib.get_entries()
    for i, entry in enumerate(entries):
        if tag != None and not cplib.tag_included(tag, entry['tags']):
            continue

        line0 = entry['lines'][0]
        if len(line0) > 64:
            heading = line0[0:64] + '...'
        else:
            heading = line0

        print(f'{i:03d} {entry["date"]} {heading} lines:[{entry["start"]}, {entry["end"]}]')
