#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

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

using namespace std;

struct Breakpoint {
    uintptr_t addr;
    long data;

    Breakpoint(uintptr_t address, long dataa) {
        addr = address;
        data = dataa;
    }
};

uintptr_t base_address = 0;
pid_t child_pid = -1;

bool loaded = false;
bool non_static_jmp = false;
static bool entering = true;

vector<Breakpoint> breakpoints;

void set_breakpoint(uintptr_t addr) {

    long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, nullptr);
    
    Breakpoint bp = Breakpoint(addr, data);
    breakpoints.push_back(bp);
    
    long int3 = (data & ~0xFF) | 0xCC;

    if (ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)int3) < 0) errquit("ptrace(POKETEXT)");

    if(!non_static_jmp) printf("** set a breakpoint at 0x%lx.\n", addr);
}

void disassemble(pid_t pid, uintptr_t rip) {
    constexpr int INSN_BUF_SIZE = 64;
    uint8_t code[INSN_BUF_SIZE];

    for(int i = 0; i < INSN_BUF_SIZE; i += sizeof(long)) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, pid, rip + i, nullptr);
        if(errno != 0) errquit("ptrace(PEEKDATA)");
        memcpy(code + i, &data, sizeof(long));
    }

    csh handle;
    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) errquit("Capstone Initialize Failed");
    
    cs_insn *insn;
    size_t count = cs_disasm(handle, code, INSN_BUF_SIZE, rip, 5, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
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

        cs_free(insn, count);
    }
    else printf("** the address is out of the range of the executable region.\n");

    cs_close(&handle);

}

void reset_breakpoint() {
    if(breakpoints.size() == 0) return;

    for(int i = breakpoints.size() - 1; i >= 0; i--) {
        if (ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, (void*)breakpoints[i].data) < 0) 
            errquit("Failed to reset breakpoint");
    }
}

void set_breakpoint() {
    for (size_t i = 0; i < breakpoints.size(); i++) {
        long int3 = (breakpoints[i].data & ~0xFF) | 0xCC;
        if (ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, (void*)int3) < 0) 
            errquit("Failed to set breakpoint");
    }
}

bool hit_breakpoint(uintptr_t rip, long &data) {
    for(size_t i = 0; i < breakpoints.size(); i++) {
        if (rip == breakpoints[i].addr) {
            data = breakpoints[i].data;
            return true;
        }
    }

    return false;
}

void step_instruction() {
    int status;

    reset_breakpoint();

    if(ptrace(PTRACE_SINGLESTEP, child_pid, nullptr, nullptr) < 0) errquit("ptrace(SINGLESTEP)");

    waitpid(child_pid, &status, 0);

    if(WIFEXITED(status)) {
        puts("** the target program terminated.");
        return;
    }

    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0) errquit("ptrace(GETREGS)");

    long data;
    bool hit = hit_breakpoint(regs.rip, data);
    if(hit) printf("** hit a breakpoint at 0x%llx.\n", regs.rip);

    disassemble(child_pid, regs.rip);

    set_breakpoint();
}

void continue_execution() {
    int status;
    if(ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) < 0) errquit("ptrace(SINGLESTEP)");
    waitpid(child_pid, &status, 0);

    for(size_t i = 0; i < breakpoints.size(); i++) {
        long int3 = (breakpoints[i].data & ~0xFF) | 0xCC;
        if(ptrace(PTRACE_POKETEXT, child_pid, breakpoints[i].addr, int3));
    }

    if(ptrace(PTRACE_CONT, child_pid, 0, 0) < 0) errquit("ptrace(CONT)");
    waitpid(child_pid, &status, 0);
    
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == 0) {
        long data;
        bool hit = hit_breakpoint(regs.rip - 1, data);
        if(hit) {
            if(!non_static_jmp) printf("** hit a breakpoint at 0x%llx.\n", regs.rip - 1);
            if(ptrace(PTRACE_POKETEXT, child_pid, regs.rip - 1, data) < 0) errquit("ptrace(POKETEXT)");
            regs.rip--;
            if(ptrace(PTRACE_SETREGS, child_pid, 0, &regs) < 0) errquit("ptrace(SETREGS)");
        }

        if(!non_static_jmp) disassemble(child_pid, regs.rip);
    }
    if (WIFEXITED(status)) {
        printf("** the target program terminated.\n");
        loaded = false;
    }
}

void delete_breakpoint(int index) {
    if(index < 0 || index >= (int)breakpoints.size()) {
        printf("** breakpoint %d does not exist.\n", index);
        return;
    }

    if (ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[index].addr, (void*)breakpoints[index].data) < 0) errquit("ptrace(POKETEXT)");

    breakpoints.erase(breakpoints.begin() + index);
    printf("** delete breakpoint %d.\n", index);
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

void list_breakpoints() {
    printf("Num     Address\n");
    for(size_t i = 0; i < breakpoints.size(); i++)
        printf("%-6ld  0x%lx\n", i, breakpoints[i].addr);
}

uintptr_t parse_address(const char *str) {
    uintptr_t addr;
    if(strncmp(str, "0x", 2) == 0) sscanf(str, "%lx", &addr);
    else sscanf(str, "%lx", &addr);

    return addr;
}

void load_program(const char* file_path) {
    if(loaded) {
        puts("Program has been loaded");
        return;
    }

    child_pid = fork();

    if(child_pid == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
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
            long entry_point = base_address + elf_header.e_entry;
            printf("** program '%s' loaded. entry point: 0x%lx.\n", file_path, entry_point);
            disassemble(child_pid, entry_point);

            set_breakpoint(entry_point);
            continue_execution();
            non_static_jmp = false;
        }
        else {
            printf("** program '%s' loaded. entry point: 0x%lx.\n", file_path, (long)elf_header.e_entry);
            disassemble(child_pid, regs.rip);
        }
    }
    else errquit("fork failed");

}

void trace_syscall() {
    int status;
    ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
    waitpid(child_pid, &status, 0);

    if (WIFSTOPPED(status)) {
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0)
            errquit("ptrace(GETREGS)");

        uintptr_t rip = regs.rip - 1;

        for (size_t j = 0; j < breakpoints.size(); j++) {
            if (breakpoints[j].addr == rip) {
                printf("** hit a breakpoint at 0x%lx.\n", rip);

                long data = ptrace(PTRACE_PEEKDATA, child_pid, rip, NULL);
                ptrace(PTRACE_POKEDATA, child_pid, rip, (data & ~0xff) | breakpoints[j].data);

                regs.rip = rip;
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
                waitpid(child_pid, NULL, 0);

                data = ptrace(PTRACE_PEEKDATA, child_pid, rip, NULL);
                breakpoints[j].data = data & 0xff;
                ptrace(PTRACE_POKEDATA, child_pid, rip, (data & ~0xff) | 0xcc);

                disassemble(child_pid, rip + 1);
                return;
            }
        }

        if (regs.orig_rax > 300) {
            printf("** hit an unknown syscall-like instruction at 0x%llx.\n", regs.rip - 1);
            disassemble(child_pid, regs.rip - 1);
        } 
        else if (entering) {
            printf("** enter a syscall(%lld) at 0x%llx.\n", regs.orig_rax, regs.rip - 2);
            disassemble(child_pid, regs.rip - 2);
            entering = false;
        } 
        else {
            printf("** leave a syscall(%lld) = %lld at 0x%llx.\n", regs.orig_rax, regs.rax, regs.rip - 2);
            disassemble(child_pid, regs.rip - 2);
            entering = true;
        }
    } 
    else if (WIFEXITED(status)) {
        printf("** the target program terminated.\n");
        return;
    }
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
        load_program(file_path);
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
        puts("I haven't implement... It still has some bugs");
        // istringstream iss(cmd + 6);
        // string addr_str, hex_str;
        // if(iss >> addr_str >> hex_str) patch_memory(addr_str, hex_str);
        // else puts("** usage: patch <hex address> <hex string>");
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