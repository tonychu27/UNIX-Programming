#!/usr/bin/env python3
# -*- coding: utf-8 -*-
## Lab sample file for the AUP course by Chun-Ying Huang

import sys
import base64
import zlib
from itertools import permutations
from pwn import *
from solpow import solve_pow

if len(sys.argv) > 1:
    ## for remote access
    r = remote('up.zoolab.org', 10155)
    solve_pow(r)
else:
    ## for local testing
    r = process('./server.py', shell=False)

def recvmsg():
    """Receives a base64 encoded and zlib compressed message from the server, then decodes it."""
    msg = r.recvline().strip()
    msg = base64.b64decode(msg)
    mlen = int.from_bytes(msg[0:4], 'little')  # Extract length (little-endian)

    decompressed_msg = zlib.decompress(msg[4:]).decode()
    return decompressed_msg

def sendmsg(msg):
    """Encodes and sends a message to the server using little-endian length encoding."""
    zm = zlib.compress(msg.encode())
    mlen = len(zm)
    encoded_msg = base64.b64encode(mlen.to_bytes(4, 'little') + zm).decode()
    r.sendline(encoded_msg.encode())

def feedback():
    msg = recvmsg()
    msg = msg.encode()

    a = int.from_bytes(msg[:4], 'big')
    b = int.from_bytes(msg[5:9], 'big')

    return a, b

def generate_guesses():
    """Generate all 4-digit numbers with unique digits."""
    guesses = []
    for i in range(10000):
        guess = f"{i:04d}"
        if len(set(guess)) == 4:
            guesses.append(guess)
    return guesses

def feedback_is_valid(guess, a, b, previous_guess):
    correct_a = sum(1 if guess[i] == previous_guess[i] else 0 for i in range(4))
    correct_b = sum(1 if guess[i] in previous_guess else 0 for i in range(4)) - correct_a

    return correct_a == a and correct_b == b

print('*** Implement your solver here ...')

# Receive the welcome message
print(recvmsg())

numbers = ["".join(p) for p in permutations("0123456789", 4)]

for attempt in range(10):
    print(recvmsg())

    if attempt == 0:
        guess = "1234"
    elif attempt == 1:
        guess = "5678"

    sendmsg(guess)

    a, b = feedback()

    print(recvmsg())

    if a == 4:
        break
    
    numbers = [n for n in numbers if feedback_is_valid(n, a, b, guess)]

    if numbers:
        guess = numbers[0]

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :