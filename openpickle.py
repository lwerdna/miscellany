#!/usr/bin/env python

import os, sys
import pprint
import pickle

fpath = sys.argv[1]

with open(fpath, 'rb') as f:
    data = pickle.load(f)

pprint.pprint(data)

#print('variable named data holds the loaded pickle')
#breakpoint()
