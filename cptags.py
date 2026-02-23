#!/usr/bin/env python

import os, sys, re, pprint

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(this_dir)
import cplib

counts = {}

if __name__ == '__main__':
    entries = cplib.get_entries()
    for i, entry in enumerate(entries):
        for tag in entry['tags']:
            counts[tag] = counts.get(tag, 0) + 1
    
    if 0:
        # print most popular tags last
        for tag in sorted(counts, key=lambda k: counts[k]):
            count = counts[tag]
            print(f'#{tag} {count}')
    else:
        # print the tags in alphabetical order
        for tag in sorted(counts):
            count = counts[tag]
            print(f'#{tag} {count}')
