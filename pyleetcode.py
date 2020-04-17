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

fpath = os.path.join(os.environ['HOME'], 'repos/lwerdna/leetcode/py')
if sys.argv[1:]:
	prob_num = sys.argv[1]
	assert re.match(r'^\d+$', prob_num)
	fpath = os.path.join(fpath, prob_num + '.py')
else:
	fpath = os.path.join(fpath, 'scratch.py')

if not os.path.exists(fpath):
	with open(fpath, 'w') as fp:
		fp.write(boilerplate)
	os.system('chmod +x %s' % fpath)

#os.system('open -a geany ' + fpath)
os.system('open -a macvim ' + fpath)

