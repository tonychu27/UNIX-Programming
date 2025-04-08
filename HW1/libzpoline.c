#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define MEMORY_SIZE 4096
#define TRAMPOLINE_SIZE 512

void trampoline() {
    printf("Hello from trampoline!\n");
}

__attribute__((constructor)) void init() {
	void *mem = mmap(0x0, MEMORY_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	
    if (mem == MAP_FAILED) {
		fprintf(stderr, "/proc/sys/vm/mmap_min_addr should be set 0\n");
		exit(1);
	}

    memset(mem, 0x90, TRAMPOLINE_SIZE);

    uint8_t *p = (uint8_t *)mem + TRAMPOLINE_SIZE;
    uintptr_t trampoline_addr = (uintptr_t)trampoline;

    *p++ = 0x48;
    *p++ = 0xb8;
    memcpy(p, &trampoline_addr, sizeof(trampoline_addr));
    p += sizeof(trampoline_addr);

    *p++ = 0xff;
    *p++ = 0xe0;

    if (mprotect(mem, MEMORY_SIZE, PROT_READ | PROT_EXEC) == -1) {
        perror("mprotect");
        exit(1);
    }
}