#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>

#define MEMORY_SIZE 4096
#define TRAMPOLINE_SIZE 512
#define TRAP asm volatile("int3");

/*** Debugging ***/
/*
    gdb /lib64/ld-linux-x86-64.so.2
    set env ZDEBUG=1
    r --preload /workspace/tony/Advanced-Programming-in-the-UNIX-Environment/HW1/libzpoline.so.2 /usr/bin/echo '7h15 15 4 l337 73x7'

*/

/*** Calling Convention ***/
/*** User Interface ***/
/*** rdi, rsi, rdx, rcx, r8, r9 ***/

/*** Syscall ***/
/*** rdi, rsi, rdx, r10, r8, r9 ***/

void leet_to_text(char *buffer) {
    char leet[] = {'o', 'i', 'z', 'e', 'a', 's', 'g', 't'};
    char digits[] = "01234567";
    
    for(int i = 0; buffer[i] != '\0'; i++) {
        for(int j = 0; j < 8; j++) {
            if(buffer[i] == digits[j]) {
                buffer[i] = leet[j];
                break;
            }
        }
    }
}

int64_t handler(int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6) {
    int64_t rax_value = 0;
    int64_t ret = 0;
    asm volatile(
        "mov %%rax, %0\n\t"
        : "=r"(rax_value)
        :
        : "memory"
    );

    if(rax_value == SYS_write && arg1 == STDOUT_FILENO) {
        char *buf = (char *)arg2;
        size_t count = (size_t)arg3;
        leet_to_text(buf);
        
        asm volatile(
            "mov %0, %%rdi \n\t"
            "mov %1, %%rsi \n\t"
            "mov %2, %%rdx \n\t"
            "mov %3, %%r10 \n\t"
            "mov %4, %%r8 \n\t"
            "mov %5, %%r9 \n\t"
            "mov %6, %%rax \n\t"
            "syscall \n\t"
            :
            : "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5), "r"(arg6), "r"(rax_value)
        );

    }

    asm volatile(
        "mov %rcx, %r10 \n\t"
        "syscall \n\t"
    );

    return ret;
}

__attribute((naked)) void trampoline() {
    
    asm volatile(
        "pop %rax \n\t" 
        "mov %r10, %rcx \n\t"
        "call handler \n\t"
        "ret\n\t" 
    );
}

void setup_trampoline() {
    void *mem = mmap(0x0, MEMORY_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

    if (mem == MAP_FAILED) {
        fprintf(stderr, "/proc/sys/vm/mmap_min_addr should be set 0\n");
        exit(1);
    }

    memset(mem, 0x90, TRAMPOLINE_SIZE);

    uint8_t *p = (uint8_t *)mem + TRAMPOLINE_SIZE;
    uintptr_t trampoline_addr = (uintptr_t)trampoline;

    *p++ = 0x50;

    *p++ = 0x48;
    *p++ = 0xB8;
    memcpy(p, &trampoline_addr, sizeof(trampoline_addr));
    p += sizeof(trampoline_addr);

    *p++ = 0xFF;
    *p++ = 0xE0;

    if (mprotect(mem, MEMORY_SIZE, PROT_READ | PROT_EXEC) == -1) {
        perror("mprotect");
        exit(1);
    }
}

void rewrite_code() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    char line[4096];
    while(fgets(line, sizeof(line), fp) != NULL) {

        if ((strstr(line, "[vdso]\n") == NULL) && (strstr(line, "[vsyscall]\n") == NULL)) {
                
            int i = 0;
            char addr[65] = {0};
            char *c = strtok(line, " ");


            while(c != NULL) {
                if(i == 0) strncpy(addr, c, sizeof(addr) - 1);
                else if(i == 1) {
                    int mem_protect = 0;
                    for(size_t j = 0; j < strlen(c); j++) {
                        if(c[j] == 'r') mem_protect |= PROT_READ;
                        if(c[j] == 'w') mem_protect |= PROT_WRITE;
                        if(c[j] == 'x') mem_protect |= PROT_EXEC;
                    }

                    if(mem_protect & PROT_EXEC) {
                        size_t k;
                        for(k = 0; k < strlen(addr); k++) {
                            if(addr[k] == '-') {
                                addr[k] = '\0';
                                break;
                            }
                        }

                        int64_t from, to;
                        from = strtol(&addr[0], NULL, 16);
                        if(from == 0) {/*** Skip it since it is trampoline code ***/ break;}
                        
                        to = strtol(&addr[k + 1], NULL, 16);

                        /*** disassemable ***/                        
                        for(int64_t j = from; j < to; j++) {
                            uint8_t *p = (uint8_t *)j;
                            
                            if(*p == 0x0f && *(p + 1) == 0x05) {

                                if(mprotect((char*)from, (size_t)(to - from), PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
                                    perror("mprotect");
                                    exit(1);
                                }
                                
                                *p = 0xFF;
                                *(p + 1) = 0xD0;
                                
                                if(mprotect((char*)from, (size_t)(to - from), PROT_READ | PROT_EXEC) == -1) {
                                    perror("mprotect");
                                    exit(1);
                                }
                            }
                        }
                        
                    }
                }

                if(i == 1) break;
                c = strtok(NULL, " ");
                i++;
            }
        }

    }

    fclose(fp);
}

__attribute__((constructor)) void init() {
	setup_trampoline();
    rewrite_code();
}