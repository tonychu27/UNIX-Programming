#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#define trap asm volatile("int3");

/*
    gdb /lib64/ld-linux-x86-64.so.2
    set env LIBZPHOOK=./logger.so 
    r --preload ./libzpoline.so /usr/bin/python3 -c 'import os; os.system("wget http://www.google.com -q -t 1")'
 */

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);

static syscall_hook_fn_t original_syscall = NULL;

static void IPv4_address(struct sockaddr *addr, char addr_str[256]) {
    struct sockaddr_in *in = (struct sockaddr_in*)addr;
    uint8_t *bytes = (uint8_t*)&in->sin_addr.s_addr;
    uint16_t port = ntohs(in->sin_port);
    
    int len = 0;
    for(int i = 0; i < 4; i++) {
        int val = bytes[i];
        char num[4];
        int n = 0;
        
        do {
            num[n++] = '0' + (val % 10);
            val /= 10;
        }while(val);

        for(int j = n - 1; j >= 0; j--) addr_str[len++] = num[j];
        if(i < 3) addr_str[len++] = '.';
    }

    addr_str[len++] = ':';
    
    char port_str[6];
    int n = 0;
    int p = port;
    do {
        port_str[n++] = '0' + (p % 10);
        p /= 10;
    }while(p);

    for(int j = n - 1; j >= 0; j--) addr_str[len++] = port_str[j];
    addr_str[len] = '\0';
}

static void IPv6_address(struct sockaddr *addr, char addr_str[256]) {
    struct sockaddr_in6 *in6 = (struct sockaddr_in6*)addr;
    uint8_t *ip6 = (uint8_t*)&in6->sin6_addr;
    uint16_t port = ntohs(in6->sin6_port);

    addr_str[0] = '[';
    int offset = 1;

    for(int i = 0; i < 16; i += 2) {
        uint16_t segment = ((uint16_t)ip6[i] << 8 | ip6[i + 1]);
        for(int j = 3; j >= 0; j--) {
            uint8_t nibble = (segment >> (j * 4)) & 0xF;
            addr_str[offset++] = (nibble < 10) ? '0' + nibble : 'a' + nibble - 10;
        }
        if(i < 14) addr_str[offset++] = ':';
    }

    addr_str[offset++] = ']';
    addr_str[offset++] = ':';

    char port_str[6];
    int len = 0;
    do {
        port_str[len++] = '0' + (port % 10);
        port /= 10;
    }while(port > 0);

    for(int i = len - 1; i >= 0; i--) addr_str[offset++] = port_str[i];
    addr_str[offset] = '\0';
}

static void unix_address(struct sockaddr *addr, char addr_str[256]) {
    struct sockaddr_un *un = (struct sockaddr_un *)addr;
    const char *prefix = "UNIX:";
    memcpy(addr_str, prefix, strlen(prefix));
    strcat(addr_str, un->sun_path); 
}

static void escape_and_print(const char *buf, size_t len) {
    fputc('"', stderr);
    for(size_t i = 0; i < len; i++) {
        unsigned char c = buf[i];
        if(c == '\n') fputs("\\n", stderr);
        else if(c == '\t') fputs("\\t", stderr);
        else if(c == '\r') fputs("\\r", stderr);
        else if(isprint(c)) fputc(c, stderr);
        else fprintf(stderr, "\\x%02x", c);
    }
    fputc('"', stderr);
}

static int64_t syscall_hook_fn(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int64_t r8, int64_t r9, int64_t rax) {

    if(rax == SYS_openat) {
        int dirfd = rdi;
        const char *pathname = (const char*)rsi;
        int flags = rdx;
        mode_t mode = r10;

        int64_t ret = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
        fprintf(stderr, "[logger] openat(%s, \"%s\", 0x%x, %#o) = %ld\n",
                dirfd == AT_FDCWD ? "AT_FDCWD" : (char[32]){0}, pathname, flags, mode, ret);
        
        if (dirfd != AT_FDCWD) fprintf(stderr, "\r[logger] openat(%d, \"%s\", 0x%x, %#o) = %ld\n",
                dirfd, pathname, flags, mode, ret);

        return ret;
    }
    else if(rax == SYS_read) {
        int fd = rdi;
        char *buf = (char*)rsi;
        size_t count = rdx;

        int64_t ret = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);

        fprintf(stderr, "[logger] read(%d, ", fd);
        size_t log_len = (ret > 32) ? 32 : (ret > 0 ? ret : 0);
        
        escape_and_print(buf, log_len);

        if (ret > 32) fputs("...", stderr);

        fprintf(stderr, ", %ld) = %ld\n", count, ret);

        return ret;
    }
    else if(rax == SYS_write) {
        int fd = rdi;
        const char *buf = (const char*)rsi;
        size_t count = rdx;

        int64_t ret = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);

        fprintf(stderr, "[logger] write(%d, ", fd);
        size_t log_len = (ret > 32) ? 32 : (ret > 0 ? ret : 0);

        escape_and_print(buf, log_len);

        if (ret > 32) fputs("...", stderr);
        fprintf(stderr, ", %ld) = %ld\n", count, ret);

        return ret;
    }
    else if(rax == SYS_connect) {
        int fd = rdi;
        struct sockaddr *addr = (struct sockaddr*)rsi;
        
        socklen_t addrlen = rdx;

        int64_t ret = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
        
        char addr_str[256];

        if(addr->sa_family == AF_INET) IPv4_address(addr, addr_str);
        else if(addr->sa_family == AF_INET6) IPv6_address(addr, addr_str);
        else if(addr->sa_family == AF_UNIX) unix_address(addr, addr_str);
        else  memcpy(addr_str, "Unknown:-", 9);

        fprintf(stderr, "[logger] connect(%d, \"%s\", %d) = %ld\n", fd, addr_str, addrlen, ret);
        return ret;
    }
    else if(rax == SYS_execve) {
        const char *filename = (const char*)rdi;
        void *argv = (void*)rsi;
        void *envp = (void*)rdx;

        fprintf(stderr, "[logger] execve(\"%s\", %p, %p)\n", filename, argv, envp);
        return original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
    }

    return original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
}

void __hook_init(const syscall_hook_fn_t trigger_syscall, syscall_hook_fn_t *hooked_syscall) {
    original_syscall = trigger_syscall;
    *hooked_syscall = syscall_hook_fn;
}