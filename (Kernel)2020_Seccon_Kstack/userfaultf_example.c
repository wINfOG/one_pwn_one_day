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
//userfault-id
#include <linux/userfaultfd.h>
#include <poll.h>

#define CMD_PUSH 0x57ac0001
#define CMD_POP 0x57ac0002

typedef struct _Element
{
	int owner;
	unsigned long value;
	struct _Element *fd;
} Element;



void * fault_handler_thread(void *arg)
{
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    static int fault_cnt = 0;     /* Number of faults so far handled */
    long uffd;                    /* userfaultfd file descriptor */
    static char *page = NULL;
    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    int page_size = sysconf(_SC_PAGE_SIZE);

    uffd = (long) arg;

    /* Create a page that will be copied into the faulting region */

    if (page == NULL) 
    {
        page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED)
            perror("[!] mmap");
    }

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
        if (nready == -1)
            perror("[!] poll");

        printf("\nfault_handler_thread():\n");
        printf("    poll() returns: nready = %d; "
                "POLLIN = %d; POLLERR = %d\n", nready,
                (pollfd.revents & POLLIN) != 0,
                (pollfd.revents & POLLERR) != 0);

        /* Read an event from the userfaultfd */

        nread = read(uffd, &msg, sizeof(msg));
        if (nread == 0)
        {
            printf("EOF on userfaultfd!\n");
            exit(EXIT_FAILURE);
        }

        if (nread == -1)
            perror("[!] read");

        /* We expect only one kind of event; verify that assumption */

        if (msg.event != UFFD_EVENT_PAGEFAULT)
        {
            fprintf(stderr, "Unexpected event on userfaultfd\n");
            exit(EXIT_FAILURE);
        }
        /* Display info about the page-fault event */

        printf("    UFFD_EVENT_PAGEFAULT event: ");
        printf("flags = %llx; ", msg.arg.pagefault.flags);
        printf("address = %llx\n", msg.arg.pagefault.address);

        /* Copy the page pointed to by 'page' into the faulting
            region. Vary the contents that are copied in, so that it
            is more obvious that each fault is handled separately. */

        memset(page, 'A' + fault_cnt % 20, page_size);
        fault_cnt++;

        uffdio_copy.src = (unsigned long) page;

        /* We need to handle page faults in units of pages(!).
        So, round faulting address down to page boundary */

        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                              ~(page_size - 1);
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            perror("[!] ioctl-UFFDIO_COPY");

        printf("        (uffdio_copy.copy returned %lld)\n",
               uffdio_copy.copy);
    }
}


/* debug
gdb -q -ex "set architecture i386:x86-64:intel" -ex "target remote localhost:3234" -ex='b * 0xffffffffc000005d' -ex='add-symbol-file ./gnote.ko 0xffffffffc0000000'
gdb -q -ex "set architecture i386:x86-64:intel" -ex "target remote localhost:3234" -ex='b * 0xffffffff81000000+0x001dd06' -ex='add-symbol-file ./gnote.ko 0xffffffffc0000000'
*/

int main(int argc, char **argv[]) {
    /*
    int fd = open("/proc/stack", O_RDWR);
    if(-1 == fd) {
        perror("[!] stack open");
    }
    */
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

    // 3. 分配一个匿名内存空间，由于是匿名空间且没有使用过，他没有对应的物理空间，在第一次使用时会触发缺页
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


    //启动 monitor 轮询线程，整个 userfaultfd 的启动流程就结束了，接下来便是等待缺页异常的过程
    pthread_t thr;
    int s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
    if (s != 0) {
        perror("[!]pthread_create\n");
    }

    //构造缺页异常
    void * ptr = (void*) *(unsigned long long*) addr;

    printf("Get data: %p\n", ptr);

    printf("[+] the end\n");
    /*
    [+] start poc
    fault_handler_thread():
        poll() returns: nready = 1; POLLIN = 1; POLLERR = 0
        UFFD_EVENT_PAGEFAULT event: flags = 0; address = 7faa81732000
            (uffdio_copy.copy returned 4096)
    Get data: 0x4141414141414141
    [+] the end
    */
    return 0;
    
}