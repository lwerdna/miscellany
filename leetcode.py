#!/usr/bin/env python

import os

boilerplate = '''
#!/usr/bin/env python3

class Solution:
	def whatever(a, b, c):
		pass

s = Solution()
r = s.whatever()
'''

fpath = '/tmp/leetcode.py'
with open(fpath, 'w') as fp:
	fp.write(boilerplate)

os.system('open -a geany ' + fpath)

