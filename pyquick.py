#!/usr/bin/env python3

# goal: type "pyquick" to immediately drop into a python type/run environment

import os

boilerplate = '''#!/usr/bin/env python3

'''

fpath = '/tmp/quick.py'
with open(fpath, 'w') as fp:
	fp.write(boilerplate)

os.system('chmod +x %s' % fpath)
os.system('open -a geany ' + fpath)

