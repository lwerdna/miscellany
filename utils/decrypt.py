#!/usr/bin/python

import os
import sys
import base64
import hashlib
import getpass
import tempfile
import platform
import subprocess
from struct import pack, unpack

G_DO_BASE64 = 1

def bitadd(a, b, regsize=32):
	return (a+b) & (2**regsize - 1)

def bitshl(a, n, regsize=32):
	return (a<<n) & (2**regsize - 1)

def xtea_encrypt_block(v, key, num_rounds=32):
	sum=0
	delta=0x9E3779B9

	[v0,v1] = unpack('>II', v) 
	subkeys = unpack('>IIII', key)

	for i in range(num_rounds):
		v0 = bitadd(v0, bitadd(( bitshl(v1, 4) ^ (v1 >> 5)), v1) ^ bitadd(sum, subkeys[sum & 3]))
		sum = bitadd(sum, delta)
		v1 = bitadd(v1, bitadd(( bitshl(v0, 4) ^ (v0 >> 5)), v0) ^ bitadd(sum, subkeys[(sum>>11) & 3]))

	return pack('>II', v0, v1)

def xtea_encrypt_ofb(plaintext, key, iv="\x41\x42\x43\x44\x45\x46\x47\x48"):
	length = len(plaintext)

	# build stream at least as long as the plaintext
	ct = iv
	stream = []
	for i in range((length + 7) / 8):
		ct = xtea_encrypt_block(ct, key)
		stream += unpack("8B", ct)

	# xor each byte
	ciphertext = ''
	for i in range(length):
		ciphertext += pack('B', ord(plaintext[i]) ^ stream[i])

	return ciphertext 

if __name__ == '__main__':
	if len(sys.argv) <= 1:
		raise Exception("supply a file to decrypt")

	fpath = sys.argv[1]
	
	# ask password
	pw = getpass.getpass()
	m = hashlib.sha1(pw)
	digest = m.digest()
	
	#print "sha1(password) = %s" % repr(digest)
	key = digest[0:16]
	#key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	#print "key = %s" % repr(key)
	
	# open file contents
	fp = open(fpath, 'r')
	body = fp.read()
	fp.close()
	
	# b64 decode, decrypt, if this is not a new file
	if len(body) > 0:
		if G_DO_BASE64:
			body = base64.b64decode(body)
	
		body = xtea_encrypt_ofb(body, key)
		#print "new body: %s" % body
	
	# make temporary file
	(tmp_handle, tmp_name) = tempfile.mkstemp(suffix=os.path.splitext(fpath)[1])
	print "writing temporary contents to %s" % tmp_name
	tmp_obj = os.fdopen(tmp_handle, 'w')
	tmp_obj.write(body)
	tmp_obj.close()
	
	# edit
	print "invoking gvim and waiting... (gvim %s)" % tmp_name
	subprocess.call(["vim", '-f', tmp_name])
	
	# now open, encode, encrypt
	print "reading changes from %s" % tmp_name
	fp = open(tmp_name)
	body = fp.read()
	fp.close()
	
	print "encrypting, encoding"
	if len(body) > 0:
		body = xtea_encrypt_ofb(body, key)
	
		if G_DO_BASE64:
			body = base64.b64encode(body)
	
	print "propogating changes to %s" % fpath
	fp = open(fpath, 'w')
	fp.write(body)
	fp.close()
	
	# delete old file
	print "wiping %s" % tmp_name
	if platform.system() == 'Darwin':
		subprocess.call(['rm', '-P', tmp_name])
	else:
		subprocess.call(["shred", '-n', '200', '-z', '-u', tmp_name])
	
	# done!
	print "done!"

