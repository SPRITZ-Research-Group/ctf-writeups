#!/usr/bin/python3

import sys
import struct

def disasm(instr):
	(opcode, opnd, n1, n2) = struct.unpack('<4I', instr)
	if opcode == 0:
		return ('inc  r{}, {}'.format(opnd, n1), [n1])
	elif opcode == 1:
		return ('cdec r{}, {}, {}'.format(opnd, n1, n2), [n1, n2])
	elif opcode == 2:
		return ('call {{{}}}, {}, {}'.format(', '.join(['r{}'.format(i) for i in range(opnd)]), n1, n2), [n1, n2])
	return ('unknown instruction {}'.format(opcode), [])

with open(sys.argv[1], 'rb') as f:
	code = f.read()[4:]

lines = []
xrefs = {}
for i in range(0, len(code) // 16):
	d, x = disasm(code[i*16:(i+1)*16])
	lines.append('{:>3}: {}'.format(i, d))
	for j in x:
		if j == i + 1:
			continue
		if j in xrefs:
			xrefs[j].append(str(i))
		else:
			xrefs[j] = [str(i)]

for i in range(len(lines)):
	line = lines[i]
	if i in xrefs:
		line += ' ; Xrefs: ' + ', '.join(xrefs[i])
	print(line)
