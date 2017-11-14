#!/usr/bin/python2

import sys

xor = lambda a, b : chr(ord(a) ^ ord(b) ^ 0x3c)

with open(sys.argv[1], 'rb') as f:
	f.seek(512)
	ctxt = f.read(512 * 24)

key = ''.join([xor(ctxt[3+i], 'WARGAMES'[i]) for i in range(8)])
key = key[-3:] + key[:-3]

print('[+] Key: {}'.format(key))

ptxt = ''.join([xor(ctxt[i], key[i%8]) for i in range(len(ctxt))])

with open(sys.argv[2], 'wb') as f:
	f.write(ptxt)
