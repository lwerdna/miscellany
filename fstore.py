#!/usr/bin/env python3

# "file store" tool - copy files to ~/fstore

import os
import re
import sys
import shutil
import hashlib

def calc_sha1(fpath):
    context = hashlib.sha1()
    with open(fpath, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            context.update(data)

    return context.hexdigest()

def get_store_path():
    return os.path.join(os.environ['HOME'], 'fstore')

def get_index_path():
    return os.path.join(get_store_path(), 'index.txt')

database = {}

def load_db():
    global database

    fpath = get_index_path()

    with open(fpath) as fp:
        for line in fp.readlines():
            if line.isspace():
                continue

            if m := re.match(r'^([A-Ha-h0-9]{8}) (.*)$', line.strip()):
                digest, descr = m.group(1, 2)
                database[digest] = descr
            else:
                print('ERROR: unable to parse database line:\n    {line}')

def save_db():
    global database

    fpath = get_index_path()

    with open(fpath, 'w') as fp:
        for digest, descr in database.items():
            fp.write(f'{digest} {descr}\n')

if __name__ == '__main__':
    if not sys.argv[1]:
        print(f'supply file name to add to file store')
        sys.exit(-1)

    fpath = sys.argv[1]
    fname = os.path.basename(fpath)
    if not os.path.exists(fpath):
        print(f'given path {fpath} does not exist')

    print(f'calculating sha1 of {fpath}')
    digest = calc_sha1(fpath)
    print(f'sha1: {digest}')

    key = digest[0:8]

    print(f'loading database...')
    load_db()

    do_copy = True
    store_path = os.path.join(get_store_path(), key)

    if key in database:
        print(f'{fpath} already in index')

        if os.path.exists(store_path):
            print(f'already in store: {store_path}')
            do_copy = False

    if do_copy:
        print(f'copying to {store_path}')
        shutil.copy2(fpath, store_path)
        database[key] = fname

    descr = database[key]
    print(f'[{descr}]({key})')

    save_db()
