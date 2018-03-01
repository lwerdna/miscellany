#!/usr/bin/env python

import re
from subprocess import Popen, PIPE

def get_capstone_output(cmd):
	process = Popen(cmd.split(), stdout=PIPE)
	(output, err) = process.communicate()
	exit_code = process.wait()
	# strip color control codes
	output = re.sub(r'\x1B\[..m', '', output)
	output = output.rstrip()
	return output

if __name__ == '__main__':
	for i in range(32):
		cmd = './capstone ppc bin 010000 00100 %s 00000000000000 00' % bin(i)[2:].rjust(5,'0')
		output = get_capstone_output(cmd)
		print '%s\t%s' % (cmd, output)
