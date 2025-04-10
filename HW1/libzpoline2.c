#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define SYS_wtrite 1

__attribute__((constructor)) void init() {
    printf("Hello from init!\n");
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    char line[4096];
    while(fgets(line, sizeof(line), fp) != NULL) {
        if (((strstr(line, "[vdso]\n") == NULL) && (strstr(line, "[vsyscall]\n") == NULL))) {
            int i = 0;
            char addr[65] = { 0 };
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
                        if(from == 0) {/**** DO trampoline ***/}
                        
                        to = strtol(&addr[k + 1], NULL, 16);
                        /*** disassemable ****/
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

int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int64_t r8, int64_t r9, int64_t orig_rax) {
    if(orig_rax == SYS_write && rdi == 1) leet_to_text((char *)rsi);

    return syscall(orig_rax, rdi, rsi, rdx, r10, r8, r9);
}