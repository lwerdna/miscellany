#!/usr/bin/env python3

# goal: type "pytime" to quickly get an environment to comparison test two execution times

import os
import sys

boilerplate = '''#!/usr/bin/env python3

trials = 50

from random import randint
from timeit import timeit

data = [randint(0,100000) for x in range(3000)]

def method0():
    #print('method0()')
    result = [0]*10000
    return result
    
def method1():
    #print('method1()')
    result = []
    for i in range(10000):
        result.append(0)
    return result

def method2():
    #print('method2()')
    result = []
    for i in range(10000):
        result = result + [0]
    return result

duration = timeit('method0()', setup="from __main__ import method0, data", number=trials)
print("method0() trials=%d avg_time=%f seconds" % (trials, duration/trials))

duration = timeit('method1()', setup="from __main__ import method1, data", number=trials)
print("method1() trials=%d avg_time=%f seconds" % (trials, duration/trials))

duration = timeit('method2()', setup="from __main__ import method2, data", number=trials)
print("method2() trials=%d avg_time=%f seconds" % (trials, duration/trials))
'''

fpath = '/tmp/pytimeit.py'
if sys.argv[1]:
    fpath = sys.argv[1]

print(f'writing {fpath}')
with open(fpath, 'w') as fp:
	fp.write(boilerplate)

os.system('chmod +x %s' % fpath)
os.system('open -a macvim ' + fpath)
#os.system('open -a geany ' + fpath)

