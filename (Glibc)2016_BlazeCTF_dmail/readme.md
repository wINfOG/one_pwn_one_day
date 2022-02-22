# Blaze CTF 2016

不是很难

我直接扣了一个2.23的libc过来

问题出在可以向存放全局指针的堆对象越界读或者写一个堆地址

# 利用方式

直接通过越界读获得unsortbin的leak

既然能越界写，那么直接想到的就是通过 fastbin-dup 错位打 malloc_hook

控制好堆分配，向被free的fastbin 写入malloc_hook - 0x23 的地址绕过fastbin大小检查