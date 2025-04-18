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
#include <dlfcn.h>
#include <sched.h>
#include <assert.h>
#include <time.h>
#include <dis-asm.h>

#define MEMORY_SIZE 4096
#define TRAMPOLINE_SIZE 512

// #define ENABLE_LEETSPEAK

#define TRAP asm volatile("int3");
#define trap asm volatile("int3");

/*** Debugging ***/
/*
    gdb /lib64/ld-linux-x86-64.so.2
    set env LIBZPHOOK=./logger.so 
    r --preload ./libzpoline.so /usr/bin/python3 -c 'import os; os.system("wget http://www.google.com -q -t 1")'
*/

/*** Calling Convention ***/

/*** User Interface ***/
/*** rdi, rsi, rdx, rcx, r8, r9 ***/

/*** Syscall ***/
/*** rdi, rsi, rdx, r10, r8, r9 ***/

extern int64_t trigger_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern void syscall_addr(void);

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
syscall_hook_fn_t hook_syscall = NULL;

void __raw_asm() {
    asm volatile(
        ".global trigger_syscall \n\t"
        "trigger_syscall: \n\t"
	    "movq 8(%rsp), %rax \n\t"
        "movq %rcx, %r10 \n\t"
    
        ".global syscall_addr \n\t"
        "syscall_addr: \n\t"
        "syscall \n\t"

        "ret \n\t"
    );
}

int64_t handler(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx __attribute__((unused)), uint64_t r8, uint64_t r9, uint64_t r10_stack, uint64_t rax_stack, uint64_t retptr) {

#ifdef ENABLE_LEETSPEAK
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
        
        return hook_syscall(rdi, (uint64_t)buf, rdx, r10_stack, r8, r9, rax_stack);
    }
#endif

    if (rax_stack == __NR_clone3) {
        uint64_t *ca = (uint64_t *) rdi;
        if (ca[0] & CLONE_VM) {
            ca[6] -= sizeof(uint64_t);
            *((uint64_t *) (ca[5] + ca[6])) = retptr;
        }
    }

    if (rax_stack == __NR_clone) {
        if (rdi & CLONE_VM) {
            rsi -= sizeof(uint64_t);
            *((uint64_t *) rsi) = retptr;
        }
    }
    
    if(hook_syscall == NULL) return trigger_syscall(rdi, rsi, rdx, r10_stack, r8, r9, rax_stack);
    return hook_syscall(rdi, rsi, rdx, r10_stack, r8, r9, rax_stack);
}

void trampoline() {
    asm volatile(
        "pushq %rbp \n\t"
        "movq %rsp, %rbp \n\t"

        "subq $128, %rsp \n\t"

        "andq $-16, %rsp \n\t"

        "pushq %r11 \n\t"
        "pushq %r9 \n\t"
        "pushq %r8 \n\t"
        "pushq %rdi \n\t"
        "pushq %rsi \n\t"
        "pushq %rdx \n\t"
        "pushq %rcx \n\t"
        
        "pushq 16(%rbp) \n\t"
        "pushq %rax \n\t"
        "pushq %r10 \n\t"

        "callq handler \n\t"

        "popq %r10 \n\t"
        "addq $16, %rsp \n\t"
        
        "popq %rcx \n\t"
        "popq %rdx \n\t"
        "popq %rsi \n\t"
        "popq %rdi \n\t"
        "popq %r8 \n\t"
        "popq %r9 \n\t"
        "popq %r11 \n\t"

        "addq $128, %rsp\n\t"

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

    if (mprotect(0, MEMORY_SIZE, PROT_READ | PROT_EXEC) == -1) {
        perror("mprotect");
        exit(1);
    }
}

struct disassembly_state {
    char *code;
    size_t off;
};

static int do_rewrite(void *data, enum disassembler_style style ATTRIBUTE_UNUSED, const char *fmt, ...) {
    struct disassembly_state *s = (struct disassembly_state *) data;
    char buf[4096];
    va_list arg;
    va_start(arg, fmt);
    vsprintf(buf, fmt, arg);
    if (!strncmp(buf, "syscall", 7) || !strncmp(buf, "sysenter", 8)) {
        uint8_t *ptr = (uint8_t *)(((uintptr_t) s->code) + s->off);
        if ((uintptr_t) ptr == (uintptr_t) syscall_addr) {
            va_end(arg);
            return 0;
        }

        ptr[0] = 0xff;
        ptr[1] = 0xd0;
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

                        struct disassembly_state s = {0};

                        if(mprotect((char*)from, (to - from), PROT_WRITE | PROT_READ | PROT_EXEC) == -1) {
                            perror("mprotect");
                            exit(EXIT_FAILURE);
                        }

                        disassemble_info disasm_info = {0};

                        init_disassemble_info(&disasm_info, &s, (fprintf_ftype)printf, do_rewrite);

                        disasm_info.arch = bfd_arch_i386;
                        disasm_info.mach = bfd_mach_x86_64;
                        disasm_info.buffer = (bfd_byte *)from;
                        disasm_info.buffer_length = (to - from);

                        disassemble_init_for_target(&disasm_info);
                        disassembler_ftype disasm;
                        
                        disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);
                        
                        s.code = (char*)from;
                        while (s.off < (to - from)) s.off += disasm(s.off, &disasm_info);
                        
                        if(mprotect((char*)from, (to - from), mem_protect) == -1) {
                            perror("mprotect");
                            exit(1);
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

void load_hook_library() {
    const char *filename = getenv("LIBZPHOOK");
    if(!filename) {
        fprintf(stderr, "env LIBZPHOOK is empty, so skip to load a hook library\n");
        return;
    }

    void *handle = dlmopen(LM_ID_NEWLM, filename, RTLD_NOW | RTLD_LOCAL);
    if(!handle) {
        fprintf(stderr, "Failed to load hook library: %s\n", dlerror());
        exit(1);
    }

    void (*hook_init)(const syscall_hook_fn_t, syscall_hook_fn_t*);
    hook_init = dlsym(handle, "__hook_init");
    if(!hook_init) {
        fprintf(stderr, "Failed to load hook init function: %s\n", dlerror());
        exit(1);
    }

    hook_syscall = trigger_syscall;
    hook_init(trigger_syscall, &hook_syscall);
}   

__attribute__((constructor)) void init() {
    setup_trampoline();
    rewrite_code();
    load_hook_library();
}