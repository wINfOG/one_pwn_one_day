# Blazeme - Blaze CTF 2018

给源码了，好事

代码很少

一眼看上去，问题肯定出现在 strncat 这种不正常逻辑的地方

然后kbuf使用了全局变量，可以竞争修改但是没有啥用

```
	if (kbuf != NULL) {
		strncat(str, kbuf, strlen(kbuf));
		printk(KERN_INFO "%s", str);
	}
```

快速入门slab+slub分配算法, 按照顺序阅读：

> http://brieflyx.me/2020/heap/linux-kernel-slab-101/

> https://blog.csdn.net/lukuen/article/details/6935068

> https://www.anquanke.com/post/id/202371

明白slub的实现方式，我们应该知道它很像glibc中fastbin的形态，但是没有chunk的结构，尝试写个简单的代码调试一下,断点下载write中的kmalloc部分，看一下多次分配后的内存结构

```
/* debug
gdb -q -ex "set architecture i386:x86-64:intel" -ex "target remote localhost:3234" -ex='b * 0xffffffffc0000000+0xb0' -ex='add-symbol-file ./blazeme.ko 0xffffffffc0000000'
*/
int main(int argc, char **argv[]) {

    int fd = open("/dev/blazeme", O_RDWR);

    char payload[64] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for(int i = 0; i < 100; i++) {
        printf("[write] index:%d\n", i);
        ssize_t w = write(fd, payload, 64);
    }
    return 0;
}
```

通过调试可以看出，很明显的单链表结构，并且一部分的地址按照0x40大小依次向下减少

```
*RAX  0xffff8800029ab740 —▸ 0xffff8800029ab700 —▸ 0xffff8800029ab140 —▸ 0xffff8800029ab100 —▸ 0xffff8800029abf80

pwndbg> telescope 0xffff8800029ab140
00:0000│  0xffff8800029ab140 —▸ 0xffff8800029ab100 —▸ 0xffff8800029abf80 —▸ 0xffff8800029ab840 —▸ 0xffff8800029abe40 ◂— ...
```

那构造方法就明显了，只要构造出连续0x40大小的内存块进行写入，不包含\0而形成栈溢出

这有2种做法，第一种通过调试定位在哪个64bit中形成溢出，这样精确的调用完成利用，这样在最后一个中可以写入一次"\0"；但是这种方法稳定性欠佳，如果攻击远程还要算上通过print传输payload的时间很难说有多少概率打通

第二种，构造出一套不包含"\0"的ROP链，直接循环写入直到碰撞出一个超过512大小的栈溢出，这种做法应该是有通用的模板写法（mmap+ROP栈迁移），在一些只能覆盖返回地址的题目上也可以这样做，而且还没有kalsr/smap/smep
```
0xffffffff81232ba5 : mov esp, 0x5b000000 ; pop r12 ; pop rbp ; ret
```
然后直接ret2user
