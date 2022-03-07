# Kstack - Seccon 2020

保护： kaslr smep

操作全局变量维护的单链表没有加锁，其它的看上去没有啥大的逻辑问题，难度在于如何竞争，链表的内存操作不是线性的，时间窗也很小，需要竞争不止一次，如果不知道 userfault-fd 技巧，这题想做出有效的竞争那会比较麻烦（泄露竞争1次，控制RIP竞争1次）；怪不得后面把这个功能加权限给ban了

# userfault—fd

> https://www.anquanke.com/post/id/253835

通过 userfaultfd 这种机制，用户可以通过自定义的 page fault handler 在用户态处理缺页异常。

其实不用知道太多，直接套模板就行，反正也记不住它的每个细节，我们知道它的整个流程作用是什么就行。

可以在缺页异常出现时把执行流切回我们可以控制的用户态，用户态可以进行一次恢复来避免这个异常，这可以让流程中断暂停。

这让我们的竞争在哪怕一个极为短暂的时间窗也可以稳定触发（当然这个竞争一定要有用户内存参与），且不会在过程中留下过多的竞争副产物。

# leak

很直接，在 CMD_PUSH + copy_from_user时通过 userfault—fd 让线程阻塞，同时使用 CMD_POP 读取内容，因为此时已经有kmalloc分配内存且放入链表中了，POP操作是可以获得未赋值的对象的。

看一下。结构体大小0x20，偏移是+8那有，shm_file_data.ipc_namespace 或者seq_operations.stop可以使用

我选择 seq_operations 这个简单

# 栈迁移+ROP

我看其它的WP有通过userfault-fd卡在POP中的copy_to_user，然后向push传入一个非法的地址构造出double-free实现控制，最后修改mod_probepath的思路。

我这个思路比较简单，还是利用seq_operations

seq_operations 的结构体包含4个pointer，可以在

>https://www.kernel.org/doc/Documentation/filesystems/seq_file.txt

看到创建和使用的逻辑，我们的竞争可以修改相同大小(0x20)的第二个元素(+8)的内容，也就是stop指针。

通过阅读代码文档以及自己调试一下知道，在close时会调用stop指针，那么我们只要通过通用的竞争手法修改这个指针到栈迁移的gadget即可。


# setxattr 堆占位

https://www.anquanke.com/post/id/266898

配合 userfault—fd 的利用机巧，因为它可以分配任意大小的kernel-space并且存在 copy_from_user 稳定触发到userfault-fd

这是查资料的时候顺便找到的，我做题没有用到


# 更多关于 Userfault-fd

https://arttnba3.cn/2021/03/03/NOTE-0X03-LINUX-KERNEL-PWN-PART-II/

重点关注

> 这意味着在较新版本内核中只有 root 权限才能使用 userfaultfd syscall

进一步搜索

建议读一下 commit+mail 信息 https://patchwork.kernel.org/project/linux-fsdevel/patch/20190319030722.12441-2-peterx@redhat.com/#22602327


```
this way is that the bpf sysctl adds the CAP_SYS_ADMIN capability
requirement, while userfaultfd adds the CAP_SYS_PTRACE requirement,
because the userfaultfd monitor is more likely to need CAP_SYS_PTRACE
already if it's doing other kind of tracking on processes runtime, in
addition of userfaultfd. In other words both syscalls works only for
root, when the two sysctl are opt-in set to 1.

Userfaultfd can be misued to make it easier to exploit existing use-after-free
(and similar) bugs that might otherwise only make a short window
or race condition available.  By using userfaultfd to stall a kernel
thread, a malicious program can keep some state, that it wrote, stable
for an extended period, which it can then access using an existing
exploit.   While it doesn't cause the exploit itself, and while it's not
the only thing that can stall a kernel thread when accessing a memory location,
it's one of the few that never needs priviledge.
```
