#!/usr/bin/env python

import os
import re
import sys
import time
import urllib
import shutil

from kblib import *

def terminal_link_file(fpath, text):
    return '\x1B]8;;file://%s\x1B\\%s\x1B]8;;\x1B\\' % (urllib.parse.quote(fpath), text)

# collect paths with date directory structure like <root>/YYYY/MM/DD
def get_date_paths(root):
    result = []

    years = [d for d in os.listdir(root) if re.match(r'^\d\d\d\d$', d)]

    for year in years:
        months = [d for d in os.listdir(os.path.join(root, year)) if re.match(r'^\d\d$', d)]

        for month in months:
            days = [d for d in os.listdir(os.path.join(root, year, month)) if re.match(r'^\d\d$', d)]

            for day in days:
                full_path = os.path.join(root, year, month, day)
                if os.path.isdir(full_path):
                    result.append(full_path)

    return result

if __name__ == '__main__':
    root = os.path.join(os.environ['HOME'], 'fdumps', 'heap')

    # collect 4 most recent daily.md
    date_paths = get_date_paths(root)

    recent = []
    for dpath in sorted(date_paths, reverse=True):
        fpath = os.path.join(dpath, 'daily.md')
        if os.path.exists(fpath):
            recent.append(fpath)
        if len(recent) >= 4:
            break

    print('most recent:')
    for fpath in recent:
        print(terminal_link_file(fpath, fpath))

    # copy most recent
    time_struct = time.localtime()
    sub_path = time.strftime('%Y/%m/%d', time_struct)
    fpath = os.path.join(root, sub_path, 'daily.md')

    if os.path.exists(fpath):
        print(f'today\'s daily exists')
    else:
        print(f'today\'s daily doesnt exist, copying {recent[0]} to {fpath}')
        shutil.copyfile(recent[0], fpath)
    os.system(f'open {fpath}')
