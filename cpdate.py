#!/usr/bin/env python

import os
import sys

from datetime import date

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(this_dir)
import cplib

if __name__ == '__main__':
    filename = cplib.get_filename()

    line = '# ' + date.today().strftime("%Y-%m-%d %A")

    print(f'appending line "{line}" to {filename}')

    with open(filename, "a") as f:
        f.write('\n' + line + '\n')

