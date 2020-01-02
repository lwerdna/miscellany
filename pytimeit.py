#!/usr/bin/env python

# goal: type "pytime" to quickly get an environment to comparison test two execution times

import os

boilerplate = '''#!/usr/bin/env python3

import time
from timeit import timeit

def foo():
    a = [0]*10000
    return 2
    
def bar():
    b = []
    for i in range(10000):
        b.append(0)
    return 3
    
trials = 500
print("trials=%d avg_time=%f seconds" % (trials, timeit(foo, number=trials) / trials))
print("trials=%d avg_time=%f seconds" % (trials, timeit(bar, number=trials) / trials))
'''

fpath = '/tmp/pytimeit.py'
with open(fpath, 'w') as fp:
	fp.write(boilerplate)

os.system('chmod +x %s' % fpath)
os.system('open -a geany ' + fpath)

