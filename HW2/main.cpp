#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <elf.h>
#include <capstone/capstone.h>

#define errquit(x) {perror(x); exit(1);}
#define SYSCALL_NUM 335

using namespace std;

struct Breakpoint {
    uintptr_t addr;
    size_t idx;
    int offset;
    long data;

    Breakpoint(uintptr_t address, size_t index, int off, long dataa) {
        addr = address;
        idx = index;
        offset = off;
        data = dataa;
    }
};

vector<Breakpoint> breakpoints;

uintptr_t base_address = 0;
uintptr_t hit_addr = -1;
uintptr_t reset_bp = 0;

size_t bp_idx = 0;

pid_t child_pid = -1;

bool loaded = false;
bool non_static_jmp = false;
bool non_static = false;
bool entering = true;
bool reset = false;

char* file;

void process_terminate() {
    puts("** the target program terminated.");
    loaded = false;
}

void disassemble(uintptr_t addr) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/mem", child_pid);

    int fd = open(path, O_RDONLY);
    if(fd == -1) errquit("Fail to open /proc/[pid]/mem");

    int INSN_BUF_SIZE = 64;
    uint8_t code[INSN_BUF_SIZE];

    size_t bytes_read = pread(fd, code, INSN_BUF_SIZE, addr);
    if(bytes_read < 0) errquit("Fail to do pread");

    close(fd);

    for(size_t k = 0; k < bytes_read; k++) {
        if(code[k] == 0xCC) {
            for(const auto &bp: breakpoints) {
                if(bp.addr == addr + k)
                    code[k] = bp.data & 0xFF;
            }
        }
    }

    csh handle;
    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) errquit("Fail to initialize capstone");

    cs_insn* insn;
    size_t count = cs_disasm(handle, code, INSN_BUF_SIZE, addr, min((int)bytes_read, 5), &insn);

    size_t i = 0;
    if (count > 0) {
        for (i = 0; i < count; i++) {
            printf("    %06lx:  ", insn[i].address);

            int byte_col = 0;
            for (int j = 0; j < insn[i].size; j++) {
                printf("%02x ", insn[i].bytes[j]);
                byte_col += 3;
            }

            const int target_col = 34;
            while (byte_col < target_col) {
                printf(" ");
                byte_col++;
            }

            printf("%-10s %s\n", insn[i].mnemonic, insn[i].op_str);
        }

        if(i < 5) printf("** the address is out of the range of the executable region.\n");

        cs_free(insn, count);
    }
    else printf("** the address is out of the range of the executable region.\n");

    cs_close(&handle);
}

long set_breakpoint_data(uintptr_t addr) {
    auto it = find_if(breakpoints.begin(), breakpoints.end(), [addr](const Breakpoint& bp) {
        return bp.addr == addr;
    });

    if (it != breakpoints.end()) return -1;

    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, child_pid, addr, nullptr);
    if(data == -1 && errno != 0) {
        uintptr_t aligned = addr & ~0x7;
        int offset = addr - aligned;

        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, child_pid, aligned, nullptr);
        if(word == -1 && errno != 0) {
            puts("** the target address is not valid.");
            return -1;
        }

        uint8_t* bytes = reinterpret_cast<uint8_t*>(&word);
        long orig_data = (long)bytes[offset];
        bytes[offset] = 0xCC;

        if(ptrace(PTRACE_POKEDATA, child_pid, aligned, *(long*)bytes) < 0) errquit("Fail to poke data when setting breakpoint");

        if(!non_static_jmp) printf("** set a breakpoint at 0x%lx.\n", addr);

        breakpoints.push_back({addr, bp_idx++, offset, orig_data});
        return -1;
    }
    
    long int3 = (data & ~0xFF) | 0xCC;
    if(ptrace(PTRACE_POKEDATA, child_pid, addr, int3) < 0) errquit("Fail to poke data when setting breakpoint");
    return data;
}

void set_breakpoint(uintptr_t addr, bool printed=true) {
    long data = set_breakpoint_data(addr);
    if(data == -1) return;

    breakpoints.push_back(Breakpoint(addr, bp_idx++, 0, data));

    if(!non_static_jmp && printed) printf("** set a breakpoint at 0x%lx.\n", addr);
}

void delete_breakpoint(size_t index) {
    if(index >= breakpoints.size() || index < 0) {
        printf("** breakpoint %ld doesn't exist.\n", index);
        return;
    }

    auto it = find_if(breakpoints.begin(), breakpoints.end(), [index](const Breakpoint& bp) {
        return bp.idx == index;
    });

    if(it == breakpoints.end()) {
        printf("** breakpoint %ld doesn't exist.\n", index);
        return;
    }

    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, child_pid, breakpoints[index].addr, nullptr);
    if(data == -1 && errno != 0) errquit("Fail to peek data when deleting breakpoint");

    if(ptrace(PTRACE_POKEDATA, child_pid, breakpoints[index].addr, (data & ~0xFF) | breakpoints[index].data) < 0)
        errquit("Fail to poke data when deleting breakpoint");
    
    breakpoints.erase(it);
    printf("** delete breakpoint %ld.\n", index);
}

void hit_breakpoint(uintptr_t rip) {
    if(!non_static_jmp) printf("** hit a breakpoint at 0x%lx.\n", rip);

    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0) errquit("Fail to get regs when hitting breakpoint");

    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, child_pid, rip, nullptr);
    if(data == -1 && errno != 0) {
        uintptr_t aligned = rip & ~0x7;

        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, child_pid, aligned, nullptr);
        
        if(word == -1 && errno != 0) errquit("Fail to peek data when hitting breakpoint");

        for(const auto &bp: breakpoints) {
            if(bp.addr == rip) {
                uint8_t* bytes = reinterpret_cast<uint8_t*>(&word);
                bytes[bp.offset] = bp.data;

                if(ptrace(PTRACE_POKEDATA, child_pid, aligned, *(long*)bytes) < 0)
                    errquit("Fail to poke data when hitting breakpoint");
                break;
            }
        }
    }
    else {
        for(const auto &bp: breakpoints) {
            if(bp.addr == rip) {
                if(ptrace(PTRACE_POKEDATA, child_pid, rip, (data & ~0xFF) | bp.data) < 0)
                    errquit("Fail to poke data when hitting breakpoint");
                break;
            }
        }
    }

    if(ptrace(PTRACE_SINGLESTEP, child_pid, nullptr, nullptr) < 0) errquit("Fail to do single step when hitting breakpoint");
    waitpid(child_pid, nullptr, 0);

    reset = true;
    reset_bp = rip;

    regs.rip = rip;
    if(ptrace(PTRACE_SETREGS, child_pid, nullptr, &regs) < 0) errquit("Fail to set reg when hitting breakpoint");
}

void reset_breakpoint() {
    if (reset_bp) {
        if (reset) reset = 0;
        else {
            set_breakpoint(reset_bp, false);
            reset_bp = 0;
        }
    }
}

void step_instruction() {
    reset_breakpoint();

    if(ptrace(PTRACE_SINGLESTEP, child_pid, nullptr, nullptr) < 0) errquit("Fail to do single step when doing si");
    waitpid(child_pid, nullptr, 0);

    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0) errquit("Fail to get regs when doing si");
    
    uintptr_t rip  =regs.rip;

    auto it = find_if(breakpoints.begin(), breakpoints.end(), [rip](const Breakpoint& bp) {
        return bp.addr == rip;
    });

    if (it != breakpoints.end()) hit_breakpoint(rip);
    
    disassemble(rip);
}

void continue_execution() {
    int status;

    reset_breakpoint();

    if(ptrace(PTRACE_CONT, child_pid, nullptr, nullptr) < 0) errquit("Fail to continue when doing cont");    
    waitpid(child_pid, &status, 0);

    if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        struct user_regs_struct regs;
        if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0) errquit("Fail to get regs when doing cont");

        hit_breakpoint(regs.rip - 1);
        if(!non_static_jmp) disassemble(regs.rip - 1);
    }
    else process_terminate();
}


void patch_memory(uint64_t addr, uint64_t value, int len) {
    errno = 0;

    long existing = ptrace(PTRACE_PEEKDATA, child_pid, (void*)addr, NULL);
    if (existing == -1 && errno != 0) {
        puts("** the target address is not valid.");
        return;
    }
        
    uint64_t mask = (1ULL << (len * 8)) - 1;
    
    long new_value = (existing & ~mask) | (value & mask);

    if (ptrace(PTRACE_POKEDATA, child_pid, (void*)addr, (void*)new_value) < 0) errquit("Fail to poke data when patching");
    
    for(size_t i = 0; i < breakpoints.size(); i++){
        if (((existing >> (i * 8)) & 0xFF) == 0xCC) 
            set_breakpoint(addr + i);
    }

    printf("** patch memory at address 0x%lx.\n", addr);
}

void trace_syscall() {
    reset_breakpoint();

    int status;
    if(ptrace(PTRACE_SYSCALL, child_pid, nullptr, nullptr) < 0) errquit("Fail to trace syscall");
    waitpid(child_pid, &status, 0);

    if(WIFSTOPPED(status)) {
        struct user_regs_struct regs;
        if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0) errquit("Fail to get regs when tracing syscall");

        if(regs.orig_rax > SYSCALL_NUM) {
            hit_breakpoint(regs.rip - 1);
            disassemble(regs.rip - 1);
        }
        else if (entering) {
            printf("** enter a syscall(%lld) at 0x%llx.\n", regs.orig_rax, regs.rip - 2);
            disassemble(regs.rip - 2);
            entering = false;
        } 
        else {
            printf("** leave a syscall(%lld) = %lld at 0x%llx.\n", regs.orig_rax, regs.rax, regs.rip - 2);
            disassemble(regs.rip - 2);
            entering = true;
        }
    } 
    else if (WIFEXITED(status)) process_terminate();
}

void load_program(const char* file_path) {
    if(loaded) {
        puts("Program has been loaded");
        return;
    }

    file = new char[strlen(file_path) + 1];
    strcpy(file, file_path);
    child_pid = fork();

    if(child_pid == 0) {
        if(ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) errquit("ptrace(TRACEME)");
        execl(file_path, file_path, nullptr);
        errquit("execl failed");
    }
    else if(child_pid > 0) {
        int status;
        waitpid(child_pid, &status, 0);

        char abs_path[PATH_MAX];
        realpath(file_path, abs_path);

        char maps_path[64];
        sprintf(maps_path, "/proc/%d/maps", child_pid);
        FILE* maps = fopen(maps_path, "r");
        if(!maps) errquit("fopen maps");

        char line[256];
        while(fgets(line, sizeof(line), maps)) {
            if (strstr(line, "r--p") && strstr(line, abs_path)) {
                sscanf(line, "%lx-", &base_address);
                break;
            }
        }

        fclose(maps);
        if (base_address == 0) {
            puts("** failed to find base address.");
            return;
        }

        int fd = open(file_path, O_RDONLY);
        if(fd < 0) errquit("open failed");

        Elf64_Ehdr elf_header;
        read(fd, &elf_header, sizeof(elf_header));
        loaded = true;
        close(fd);

        struct user_regs_struct regs;
        if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0) errquit("ptrace(GETREGS)");

        /*** handling non-static binary ***/
        if(elf_header.e_entry != regs.rip) {
            non_static_jmp = true;
            non_static = true;
            long entry_point = base_address + elf_header.e_entry;
            printf("** program '%s' loaded. entry point: 0x%lx.\n", file_path, entry_point);
            disassemble(entry_point);

            set_breakpoint(entry_point);
            continue_execution();
            non_static_jmp = false;
        }
        else {
            printf("** program '%s' loaded. entry point: 0x%lx.\n", file_path, (long)elf_header.e_entry);
            disassemble(regs.rip);
        }
    }
    else errquit("fork failed");

}

void list_breakpoints() {
    printf("Num     Address\n");
    for(const auto &bp: breakpoints)
        printf("%-6ld  0x%lx\n", bp.idx, bp.addr);
}

uintptr_t parse_address(const char *str) {
    uintptr_t addr;
    if(strncmp(str, "0x", 2) == 0) sscanf(str, "%lx", &addr);
    else sscanf(str, "%lx", &addr);

    return addr;
}

void list_registers() {
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0) errquit("ptrace(GETREGS)");

    printf("$rax 0x%016llx    $rbx 0x%016llx    $rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
    printf("$rdx 0x%016llx    $rsi 0x%016llx    $rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
    printf("$rbp 0x%016llx    $rsp 0x%016llx    $r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8);
    printf("$r9  0x%016llx    $r10 0x%016llx    $r11 0x%016llx\n", regs.r9, regs.r10, regs.r11);
    printf("$r12 0x%016llx    $r13 0x%016llx    $r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
    printf("$r15 0x%016llx    $rip 0x%016llx    $eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
}

void handler(char* cmd) {
    if(!strncmp(cmd, "q", 1) || !strcmp(cmd, "exit\n")) {
        puts("Thanks for using our debugger. We hope you have a nice day!");
        exit(0);
    }

    if(!loaded && strncmp(cmd, "load ", 5) != 0) {
        cout << "** please load a program first.\n";
        return;
    }

    if(!strcmp(cmd, "si\n")) step_instruction();
    else if(!strcmp(cmd, "cont\n")) continue_execution();
    else if(!strcmp(cmd, "info reg\n")) list_registers();
    else if(!strcmp(cmd, "info break\n")) list_breakpoints();
    else if(!strcmp(cmd, "syscall\n")) trace_syscall();
    else if(!strncmp(cmd, "delete ", 7)) {
        int index;
        if(sscanf(cmd + 7, "%d", &index) == 1) delete_breakpoint(index);
        else puts("** usage: delete <breakpoint number>");
    }
    else if(!strncmp(cmd, "load ", 5)) {
        char *file_path = cmd + 5;
        int length = 0;
        while(file_path[length] != '\n') length++;
        file_path[length] = '\0';
        if(length != 0) load_program(file_path);
        else puts("** usage: load <process>");
    }
    else if(!strncmp(cmd, "break ", 6)) {
        uintptr_t addr = parse_address(cmd + 6);
        set_breakpoint(addr);
    }
    else if(!strncmp(cmd, "breakrva ", 9)) {
        uintptr_t offset = parse_address(cmd + 9);
        uintptr_t addr = base_address + offset;
        set_breakpoint(addr);
    }
    else if(!strncmp(cmd, "patch", 5)) {
        istringstream iss(cmd + 6);
        string addr_str, hex_str;
        if(iss >> addr_str >> hex_str) {
            if(hex_str.length() >= 2048 || hex_str.length() % 2) {
                puts("** the target address is not valid.");
                return;
            }

            uintptr_t addr = stoul(addr_str, nullptr, 16);
            uint64_t value = stoull(hex_str, nullptr, 16);
            int len = to_string(value).length() / 2;

            patch_memory(addr, value, len);
        }
        else puts("** usage: patch <hex address> <hex string>");
    }
    else puts("Unknown Command....");
    
}

int main(int argc, char** argv) {
    if(argc == 2) load_program(argv[1]);
    
    while(true) {
        char cmd[128];
        cout << "(sdb) ";

        if(fgets(cmd, sizeof(cmd), stdin) == nullptr) {
            printf("\n");
            continue;
        }

        handler(cmd);
    }

    return 0;
}