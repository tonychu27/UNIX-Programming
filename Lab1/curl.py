from pwn import *

context.log_level = 'info'

host = "ipinfo.io"
port = 80
path = "/ip"

conn = remote(host, port)

request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
conn.send(request)

response = conn.recvall().decode()

ip_address = response.split("\r\n\r\n")[-1].strip()

log.success(ip_address)