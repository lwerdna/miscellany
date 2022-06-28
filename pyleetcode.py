#!/usr/bin/env python3

# goal: quickly drop into a python leetcode type+run environment

import os
import re
import sys

boilerplate = '''#!/usr/bin/env python3

class Solution:
    def problemName(self, s):
        return "hi"

tests = []
tests.append(([1,2,3], [1,3,2]))
tests.append(([3,2,1], [1,2,3]))
tests.append(([1,1,5], [1,5,1]))

sol = Solution()
for (inp, expected) in tests:
    out = sol.problemName(inp)
    print('on input: ', inp, ' got output: ', out)
    if out != expected:
        print('expected: ', expected)
        assert False
'''

fname = 'go.py'
if sys.argv[1:]:
    fname = sys.argv[1]

if os.path.exists(fname):
    print('file exists')
    sys.exit(-1)

with open(fname, 'w') as fp:
	fp.write(boilerplate)
os.system('chmod +x %s' % fname)

#os.system('open -a geany ' + fname)
os.system('open -a macvim ' + fname)

