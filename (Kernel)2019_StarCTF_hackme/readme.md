# STAR_CTF_2019 hackme

直接看下来，代码问题还是很直观的，汇总一下各种信息与思路

1、先看到操作了全局的pool就直接考虑没有加锁竞争的问题，这可以构造出UAF，不过有更好用的越界读写，这个点后续不考虑。

2、传入结构体的第一个和第四个参数基本上read/write时都没有校验，可以越界读写kenrel堆的相对偏移，那这题就简单多了。

3、IOCTL会2次调用copy_from/to_user 可以通过double-fetch的方法修改内容指针？但是这看上去在这个题的逻辑里没有用啊

4、kmalloc申请大小可直接控制，很好，有很多可用的结构体。

5、保护开了KASLR SMAP SMEP; 题目居然还给了kernel的编译信息，那就不用脚本验证可以直接看到 CONFIG_STATIC_USERMODEHELPER 没有开，那可以打 modprobe_path; 

6、config里内核版本是4.20.13 这个版本cred_jar从kmmalloc-192里独立了，通过cat /proc/slabinfo 也能找cred_jar，那么直接UAF去打cred.euid是无法分配到的

7、config里内核的CONFIG_SYSVIPC没有开，无法通过shmget/shmat玩耍


# Leak base

能够通过 IOCTL == 0x30003 任意读，但是要绕过```pool[index]```存在，以及一个长度判断，如果搞不清楚实际逻辑，可以通过调试大概看一下（其实也不用）

虽然shmget/shmat的shm_file_data用不了，但是还有 seq_operations /subprocess_info / tty_struct 等等都可以玩耍

选择 seq_operations 这个代码最少的方法，构造好堆：创建 1、2、3 删除2 再创建seq_operations 通过3向前越界读来leak地址

# Write modprobe_path

可以通过修改msg_msg的next指针方法去打 modprobe_path （这题我没尝试）

不过这题的条件太好了，直接修改free-list中的next指针为leak出来的mod_prob就行了

流程

1、越界写修改free node -> next

2、分配2次同样大小的堆块

3、第二次就是 modprobe_path 直接写入模板的目标路径

4、释放几个同样大小的堆块，保证有可用的free-node坚持到我们脚本结束

5、触发 modprobe_path