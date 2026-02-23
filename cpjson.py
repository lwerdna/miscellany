#!/usr/bin/env python

import os
import re
import sys
import json
import pprint

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(this_dir)
import cplib

if __name__ == '__main__':
    entries = cplib.get_entries()
    print(json.dumps(entries, indent=4))
