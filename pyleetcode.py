#!/usr/bin/env python

# goal: quickly drop into a python leetcode type+run environment

import os

boilerplate = '''#!/usr/bin/env python3

class Solution:
	def whatever(self, a, b, c):
		pass

s = Solution([1,2,3,4], 5)
r = s.whatever()
'''

fpath = '/tmp/leetcode.py'
with open(fpath, 'w') as fp:
	fp.write(boilerplate)

os.system('chmod +x %s' % fpath)
os.system('open -a geany ' + fpath)

