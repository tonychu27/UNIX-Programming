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
#define trap asm volatile("int3");

/*** Debugging ***/
/*
    gdb /lib64/ld-linux-x86-64.so.2
    r --preload ./libzpoline.so.2 /usr/bin/echo '7h15 15 4 l337 73x7'
*/

/*** Calling Convention ***/

/*** User Interface ***/
/*** rdi, rsi, rdx, rcx, r8, r9 ***/

/*** Syscall ***/
/*** rdi, rsi, rdx, r10, r8, r9 ***/

extern int64_t trigger_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern void syscall_addr(void);

void __raw_asm() {
    asm volatile(
        ".global trigger_syscall \n\t"
        "trigger_syscall: \n\t"
        "movq %rdi, %rax \n\t"
	    "movq %rsi, %rdi \n\t"
	    "movq %rdx, %rsi \n\t"
	    "movq %rcx, %rdx \n\t"
	    "movq %r8, %r10 \n\t"
	    "movq %r9, %r8 \n\t"
	    "movq 8(%rsp),%r9 \n\t"
        ".global syscall_addr \n\t"
        "syscall_addr: \n\t"
        "syscall \n\t"
        "ret \n\t"
    );
}

int64_t handler(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8, uint64_t r9, uint64_t r10_stack, uint64_t rax_stack) {

    if(rax_stack == SYS_write && rdi == STDOUT_FILENO) {

        char *buf = (char *)rsi;

        for(size_t i = 0; buf[i] != '\0'; i++) {
            switch(buf[i]) {
                case '0': buf[i] = 'o'; break;
                case '1': buf[i] = 'i'; break;
                case '2': buf[i] = 'z'; break;
                case '3': buf[i] = 'e'; break;
                case '4': buf[i] = 'a'; break;
                case '5': buf[i] = 's'; break;
                case '6': buf[i] = 'g'; break;
                case '7': buf[i] = 't'; break;
            }
        }
        
        return trigger_syscall(rax_stack, rdi, (uint64_t)buf, rdx, r10_stack, r8, r9);
    }

    return trigger_syscall(rax_stack, rdi, rsi, rdx, r10_stack, r8, r9);
}

void trampoline() {
    asm volatile(
        "pushq %rbp \n\t"
        "movq %rsp, %rbp \n\t"
        "andq $-16, %rsp \n\t"

        "pushq %rax \n\t"
        "pushq %r10 \n\t"

        "callq handler \n\t"

        "popq %r10 \n\t"
        "addq $8, %rsp \n\t"
        "leaveq \n\t"
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

    /*** Move trampoline's address into r11 ***/
    *p++ = 0x49;
    *p++ = 0xBB;
    memcpy(p, &trampoline_addr, sizeof(trampoline_addr));
    p += sizeof(trampoline_addr);

    /*** jmp r11 ***/
    *p++ = 0x41;
    *p++ = 0xFF;
    *p++ = 0xE3;

    if (mprotect(0, MEMORY_SIZE, PROT_EXEC) == -1) {
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
                        if(from >= 0 && from <= 512) {/*** Skip it since it is trampoline code ***/ break;}
                        
                        to = strtol(&addr[k + 1], NULL, 16);

                        /*** disassemable ***/                        
                        for(int64_t j = from; j < to; j++) {
                            uint8_t *p = (uint8_t *)j;
                            
                            if(*p == 0x0F && *(p + 1) == 0x05) {
                                if((uintptr_t) p == (uintptr_t) syscall_addr) continue;

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