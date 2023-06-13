#!/usr/bin/env python

import os, sys, re, pprint

def get_files(ext=''):
    return sum([[os.path.join(r, f) for f in
        [f for f in fs if f.endswith(ext)]]
        for (r,d,fs) in os.walk('.')], [])

def ignored(fpath):
    for x in ['/.git/', '/__pycache__/']:
        if x in fpath:
            return True

    return False

if __name__ == '__main__':

    for fpath in get_files():
        if ignored(fpath):
            continue

        print(f'[{fpath}]({fpath})')

