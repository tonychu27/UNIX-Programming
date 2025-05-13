#include <iostream>
#include <fstream>
#include <sstream>

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

#define BREAKPOINT_SIZE 64
#define errquit(x) {perror(x); exit(1);}

using namespace std;

struct Breakpoint {
    uintptr_t addr;
    long data;
    bool enabled;
} breakpoints[BREAKPOINT_SIZE];

int breakpoint_idx = 0;

pid_t child_pid = -1;

bool loaded = false;
bool non_static = false;
bool entering = true;

uintptr_t base_address = 0;

void set_breakpoint(uintptr_t addr) {
    if(breakpoint_idx >= 64) {
        puts("Too many breakpoints...");
        return;
    }

    long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, nullptr);
    
    breakpoints[breakpoint_idx].addr = addr;
    breakpoints[breakpoint_idx].data = data;
    breakpoints[breakpoint_idx].enabled = true;
    long int3 = (data & ~0xFF) | 0xCC;

    if (ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)int3) < 0) errquit("ptrace(POKETEXT)");

    if(!non_static) printf("** set a breakpoint at 0x%lx.\n", addr);
    breakpoint_idx++;
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
    for(int i = 64 - 1; i >= 0; i--) {
        if(breakpoints[i].enabled) {
            if (ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, (void*)breakpoints[i].data) < 0) errquit("Failed to reset breakpoint");
        }
    }
}

bool hit_breakpoint() {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
  
    for (int i = 0; i < breakpoint_idx; i++) {
        if (breakpoints[i].enabled && regs.rip == breakpoints[i].addr) {
            printf("** hit a breakpoint at 0x%llx.\n", regs.rip);
            return true;
        }
    }
    return false;
}

void set_breakpoint() {
    for (int i = 0; i < 64; i++) {
        if (breakpoints[i].enabled) {
            long int3 = (breakpoints[i].data & ~0xFF) | 0xCC;
            if (ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, (void*)int3) < 0) errquit("Failed to set breakpoint");
        }
    }
}

void patch_memory(string addr_str, string hex_str) {
    uintptr_t patch_addr;
    try {
        patch_addr = stoul(addr_str, nullptr, 16);
    }
    catch (...) {
        puts("** the target address is not valid");
        return;
    }

    if(hex_str.length() > 2048 || hex_str.length() %2 != 0) {
        puts("** the target address is not valid");
        return;
    }

    size_t byte_len = hex_str.length() / 2;
    uint8_t* bytes = new uint8_t[byte_len];

    for(size_t i = 0; i < byte_len; i++) {
        string byte_str = hex_str.substr(i * 2, 2);
        try {
            bytes[i] = static_cast<uint8_t>(stoi(byte_str, nullptr, 16));
        } 
        catch (...) {
            delete[] bytes;
            puts("** the target address is not valid.");
            return;
        }
    }

    for (size_t i = 0; i < byte_len; i += sizeof(long)) {
        errno = 0;
        ptrace(PTRACE_PEEKDATA, child_pid, (void*)(patch_addr + i), nullptr);
        if (errno != 0) {
            delete[] bytes;
            puts("** the target address is not valid.");
            return;
        }
    }

    for (size_t i = 0; i < byte_len; i += sizeof(long)) {
        long data = 0;
        size_t copy_size = min(sizeof(long), byte_len - i);

        errno = 0;
        data = ptrace(PTRACE_PEEKDATA, child_pid, (void*)(patch_addr + i), nullptr);
        if (errno != 0) {
            delete[] bytes;
            puts("** the target address is not valid.");
            return;
        }

        memcpy((uint8_t*)&data, bytes + i, copy_size);

        for (int j = 0; j < breakpoint_idx; j++) {
            if (breakpoints[j].enabled &&
                patch_addr + i <= breakpoints[j].addr &&
                breakpoints[j].addr < patch_addr + i + copy_size) {
                size_t offset = breakpoints[j].addr - (patch_addr + i);
                ((uint8_t*)&data)[offset] = 0xCC;
            }
        }

        if (ptrace(PTRACE_POKEDATA, child_pid, (void*)(patch_addr + i), (void*)data) < 0) {
            delete[] bytes;
            errquit("ptrace(POKEDATA)");
        }
    }

    delete[] bytes;
    printf("** patch memory at 0x%lx.\n", patch_addr);
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

    hit_breakpoint();
    disassemble(child_pid, regs.rip);

    set_breakpoint();
}

void continue_execution() {

    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0) errquit("ptrace(GETREGS)");
    int index = -1;

    uint64_t rip = regs.rip;

    for (int i = 0; i < breakpoint_idx; i++) {
        if (breakpoints[i].enabled && rip == breakpoints[i].addr) {
            int status;
            index = i;
            
            ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, (void*)breakpoints[i].data);
            ptrace(PTRACE_SINGLESTEP, child_pid, nullptr, nullptr);
            
            waitpid(child_pid, &status, 0);
            
            long int3 = (breakpoints[index].data & ~0xFF) | 0xCC;
            ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[index].addr, int3);
            
            break;
        }
    }

    ptrace(PTRACE_CONT, child_pid, nullptr, nullptr);
    int status;
    waitpid(child_pid, &status, 0);

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        reset_breakpoint();

        struct user_regs_struct regs;
        if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0) errquit("ptrace(GETREGS)");
        
        uint64_t rip = regs.rip - 1;

        for (int i = 0; i < breakpoint_idx; i++) {
            if (breakpoints[i].enabled && rip == breakpoints[i].addr) {
                if(!non_static) printf("** hit a breakpoint at 0x%lx.\n", rip);
                
                ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, (void*)breakpoints[i].data);
                
                regs.rip = rip;
                
                ptrace(PTRACE_SETREGS, child_pid, nullptr, &regs);
                if(!non_static) disassemble(child_pid, rip);
                
                long int3 = (breakpoints[i].data & ~0xFF) | 0xCC;
                ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, int3);
                
                break;
            }
        }
    } 
    else if (WIFEXITED(status)) {
        printf("** the target program terminated.\n");
        loaded = false;
    }
}

void delete_breakpoint(int index) {
    if(index < 0 || index >= breakpoint_idx || !breakpoints[index].enabled) {
        printf("** breakpoint %d does not exist.\n", index);
        return;
    }

    if (ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[index].addr, (void*)breakpoints[index].data) < 0) errquit("ptrace(POKETEXT)");

    breakpoints[index].enabled = false;
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
    for(int i = 0; i < breakpoint_idx; i++) {
        if(breakpoints[i].enabled) {
            printf("%-6d  0x%lx\n", i, breakpoints[i].addr);
        }
    }
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
            non_static = true;
            long entry_point = base_address + elf_header.e_entry;
            printf("** program '%s' loaded. entry point: 0x%lx.\n", file_path, entry_point);
            disassemble(child_pid, entry_point);

            set_breakpoint(entry_point);
            continue_execution();
            non_static = true;
        }
        else {
            printf("** program '%s' loaded. entry point: 0x%lx.\n", file_path, (long)elf_header.e_entry);
            disassemble(child_pid, regs.rip);
        }
    }
    else errquit("fork failed");

}

bool is_breakpoint(uintptr_t rip) {
    for(const auto &bp: breakpoints) {
        if(bp.addr == rip) return true;
    }

    return false;
}

void trace_syscall() {

    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0) errquit("ptrace(GETREGS)");
    int index = -1;

    uint64_t rip = regs.rip;

    for (int i = 0; i < breakpoint_idx; i++) {
        if (breakpoints[i].enabled && rip == breakpoints[i].addr) {
            int status;
            index = i;
            
            ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, (void*)breakpoints[i].data);
            ptrace(PTRACE_SINGLESTEP, child_pid, nullptr, nullptr);
            
            waitpid(child_pid, &status, 0);
            
            long int3 = (breakpoints[index].data & ~0xFF) | 0xCC;
            ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[index].addr, int3);
            
            break;
        }
    }

    ptrace(PTRACE_CONT, child_pid, nullptr, nullptr);
    int status;
    waitpid(child_pid, &status, 0);
    
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        reset_breakpoint();

        struct user_regs_struct regs;
        if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0) errquit("ptrace(GETREGS)");
        
        uint64_t rip = regs.rip - 1;

        for (int i = 0; i < breakpoint_idx; i++) {
            if (breakpoints[i].enabled && rip == breakpoints[i].addr) {
                printf("** hit a breakpoint at 0x%lx.\n", rip);
                ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, (void*)breakpoints[i].data);
                
                regs.rip = rip;
                
                ptrace(PTRACE_SETREGS, child_pid, nullptr, &regs);
                disassemble(child_pid, rip);
                
                long int3 = (breakpoints[i].data & ~0xFF) | 0xCC;
                ptrace(PTRACE_POKETEXT, child_pid, (void*)breakpoints[i].addr, int3);
                
                break;
            }
        }
    }
    else if (WIFEXITED(status)) {
        printf("** the target program terminated.\n");
        return;
    }

    if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0) errquit("ptrace(GETREGS)");

    if (entering) {
        printf("** enter a syscall(%lld) at 0x%llx.\n", regs.orig_rax, regs.rip - 2);
        uint64_t rip = regs.rip - 2;
        disassemble(child_pid, rip);
    } else {
        printf("** leave a syscall(%lld) = %lld at 0x%llx.\n", regs.orig_rax, regs.rax, regs.rip - 2);
        uint64_t rip = regs.rip - 2;
        disassemble(child_pid, rip);
    }

    entering = !entering;
}

void handler(char* cmd) {
    if(!strncmp(cmd, "q", 1) || !strcmp(cmd, "exit\n")) {
        puts("Thanks for using my debugger. I hope you have a nice day!");
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