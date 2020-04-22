#!/usr/bin/env python3

import os
import re
import sys
import struct
from subprocess import Popen, PIPE

def get_program_output(cmd):					# cmd like "capstone ppc bin 000 111 11000"
	process = Popen(cmd.split(), stdout=PIPE)
	(output, err) = process.communicate()
	exit_code = process.wait()
	output = re.sub(r'\x1B\[..m', '', output)	# no color codes
	output = output.rstrip()					# no ending newline
	return output

if __name__ == '__main__':
	if not sys.argv[1:]:
		print 'ERROR: supply bits or bytes to disassemble'
		sys.exit(-1)
	
	# parse instruction word
	insword = 0
	line = ''.join(sys.argv[1:])
	if re.match(r'[01]+', line):
		insword = int(line, 2)
	else:
		insword = int(line, 16)
	print 'instruction word: 0x%08X' % insword
	
	# write instruction word to file
	with open('/tmp/disthumb.bin', 'wb') as fp:
		fp.write(struct.pack('>I', insword))
	
	# form command
	cmd = os.path.join(os.environ['HOME'], 'arm-eabi-4.8/bin/arm-eabi-objdump')
	cmd += ' --target binary'
	cmd += ' --architecture arm'
	cmd += ' --disassembler-options=force-thumb'
	cmd += ' --endian=big'
	#cmd += ' --adjust-vma=0x12345678'
	cmd += ' -D /tmp/disthumb.bin'
	
	# run it, output it
	output = get_program_output(cmd)
	for line in output.split('\n'):
		m = re.match(r'^\s+\d+:\s+(.*)', line)
		if m:
			print m.group(1)
