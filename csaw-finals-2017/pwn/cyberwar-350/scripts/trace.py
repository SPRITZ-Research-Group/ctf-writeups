#!/usr/bin/gdb -P

import gdb

class WritePixelBP(gdb.Breakpoint):
	def stop(self):
		x = int(gdb.parse_and_eval('*((short*)($sp+0))'))
		y = int(gdb.parse_and_eval('*((short*)($sp+2))'))
		#color = int(gdb.parse_and_eval('*((char*)($sp+4))'))
		addr = 0x10000 + x + 320*y
		if addr < 0xf000:
			print(x, y, hex(addr))
		return False

gdb.execute('target remote localhost:1234')
WritePixelBP('*0x3956')
gdb.execute('continue')
