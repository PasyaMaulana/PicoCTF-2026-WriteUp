#!/usr/bin/env python3
"""
Secure Dot Product - CTF Exploit
=================================
Vulnerabilities:
1. parse_vector strips '-' signs -> server computes dot(abs(v), key) instead of dot(v, key)
2. SHA-512 used without HMAC -> vulnerable to length extension attack

Exploit:
1. Query each trusted vector -> get dot(abs(v), key) as base
2. SHA-512 length extension to forge hashes for "[trusted_content + padding + ,1]"
   -> extended vector gives base_dot + key[i]
   -> key[i] = extended_result - base_result
3. Repeat for all 32 key bytes
4. Decrypt AES-CBC flag

Requirements: pip install pwntools pycryptodome
Usage: python3 exploit.py
"""

import ast
import hashlib
import re
import struct
import sys
import numpy as np
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ─────────────────── CONFIG ───────────────────
HOST = 'lonely-island.picoctf.net'
PORT = 52393
SALT_SIZE = 256
KEY_SIZE  = 32
# ──────────────────────────────────────────────


# ══════════════════════════════════════════════
#  SHA-512 Length Extension Attack
# ══════════════════════════════════════════════

def sha512_pad(msg_len: int) -> bytes:
    """Return the SHA-512 Merkle-Damgård padding for a message of msg_len bytes."""
    bit_len  = msg_len * 8
    pad      = b'\x80'
    pad_len  = (128 - (msg_len + 1 + 16) % 128) % 128
    pad     += b'\x00' * pad_len
    pad     += struct.pack('>QQ', 0, bit_len)
    return pad


def sha512_length_extend(orig_hash_hex: str, orig_msg_len: int, extension: bytes):
    """
    Given  sha512(secret ‖ message) = orig_hash_hex
    where  len(secret ‖ message)    = orig_msg_len,
    compute sha512(secret ‖ message ‖ padding ‖ extension).

    Returns (new_hash_hex, padding_bytes).
    """
    # Restore the internal hash state from the known digest
    h       = list(struct.unpack('>8Q', bytes.fromhex(orig_hash_hex)))
    padding = sha512_pad(orig_msg_len)
    new_len = orig_msg_len + len(padding) + len(extension)

    M = 2**64
    K = [
        0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
        0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
        0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
        0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
        0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
        0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
        0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
        0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
        0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
        0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
        0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
        0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
        0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817,
    ]

    def rotr(x, n): return ((x >> n) | (x << (64-n))) & (M-1)


    def compress(state, block):
        a,b,c,d,e,f,g,hv = state
        w = list(struct.unpack('>16Q', block))
        for i in range(16,80):
            s0 = rotr(w[i-15],1)^rotr(w[i-15],8)^(w[i-15]>>7)
            s1 = rotr(w[i- 2],19)^rotr(w[i-2],61)^(w[i-2]>>6)
            w.append((w[i-16]+s0+w[i-7]+s1)&(M-1))
        for i in range(80):
            S1 = rotr(e,14)^rotr(e,18)^rotr(e,41)
            ch = (e&f)^(~e&g)
            t1 = (hv+S1+ch+K[i]+w[i])&(M-1)
            S0 = rotr(a,28)^rotr(a,34)^rotr(a,39)
            mj = (a&b)^(a&c)^(b&c)
            t2 = (S0+mj)&(M-1)
            hv=g; g=f; f=e; e=(d+t1)&(M-1)
            d=c;  c=b; b=a; a=(t1+t2)&(M-1)
        return [(state[i]+[a,b,c,d,e,f,g,hv][i])&(M-1) for i in range(8)]

    ext_padded = extension + sha512_pad(new_len)
    state = h[:]
    for i in range(0, len(ext_padded), 128):
        state = compress(state, ext_padded[i:i+128])

    return struct.pack('>8Q', *state).hex(), padding


# ══════════════════════════════════════════════
#  Build a forged vector query
# ══════════════════════════════════════════════

def make_forged_query(trusted_vec, trusted_hash, extension_str):
    """
    Forge a query that:
      • passes hash verification (SHA-512 length extension)
      • parse_vector returns abs(trusted_vec) + extension_parsed

    extension_str: e.g. ',1'  or  ',0,1'  or  ',0,0,1'  …

    Returns (send_str, forged_hash, expected_parsed_vector)
      send_str: unicode-escaped string to send over the socket
    """
    content   = str(trusted_vec)[1:-1]          # strip outer [ ]
    cb        = content.encode('latin-1')
    eb        = extension_str.encode('latin-1')
    orig_len  = SALT_SIZE + len(cb)

    forged_hash, padding = sha512_length_extend(trusted_hash, orig_len, eb)

    # Full vector bytes after server does encode().decode('unicode_escape'):
    vbytes = b'[' + cb + padding + eb + b']'

    # Encode binary bytes as \\xNN escape sequences for the socket
    send = ''
    for byte in vbytes:
        c = chr(byte)
        if c in '0123456789,[] \t-':
            send += c
        elif c == '\\':
            send += '\\\\'
        else:
            send += f'\\x{byte:02x}'

    # Predict what parse_vector will return (all non-digit/bracket chars stripped)
    decoded  = vbytes.decode('latin-1')
    sanitized = ''.join(c if c in '0123456789,[]' else '' for c in decoded)
    try:
        parsed = ast.literal_eval(sanitized)
        if not isinstance(parsed, list):
            parsed = None
    except Exception:
        parsed = None

    return send, forged_hash, parsed


# ══════════════════════════════════════════════
#  Server helpers
# ══════════════════════════════════════════════

def recv_until_prompt(r):
    """Read until 'Enter your vector:' prompt and return all text received."""
    return r.recvuntil(b'Enter your vector: ', timeout=15).decode('utf-8', errors='replace')


def do_query(r, send_str, hash_str):
    """Send one query and return the integer dot-product result, or None on failure."""
    r.sendline(send_str.encode())
    resp = r.recvuntil(b'Enter its salted hash: ', timeout=10).decode('utf-8', errors='replace')
    if 'Invalid vector' in resp:
        # server continues loop without asking for hash – drain prompt
        r.recvuntil(b'Enter your vector: ', timeout=5)
        return None
    r.sendline(hash_str.encode())
    resp2 = r.recvuntil(b'Enter your vector: ', timeout=10).decode('utf-8', errors='replace')
    if 'Untrusted' in resp2:
        return None
    m = re.search(r'dot product is:\s*(-?\d+)', resp2)
    return int(m.group(1)) if m else None


def parse_trusted_from_banner(text):
    """Extract list of (vector, hash_str) from the server banner."""
    pairs = []
    pattern = r'\((\[[\d\s,\-]+\]),\s*[\'"]([0-9a-f]{128})[\'"]\)'
    for m in re.finditer(pattern, text):
        vec  = ast.literal_eval(m.group(1))
        h    = m.group(2)
        pairs.append((vec, h))
    return pairs


# ══════════════════════════════════════════════
#  AES decryption helper
# ══════════════════════════════════════════════

def try_decrypt(key_bytes, iv_hex, ct_hex):
    try:
        iv  = bytes.fromhex(iv_hex)
        ct  = bytes.fromhex(ct_hex)
        key = bytes(int(k) & 0xFF for k in key_bytes)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        text = pt.decode('utf-8', errors='replace')
        return text if ('picoCTF' in text or pt.isprintable()) else None
    except Exception:
        return None


# ══════════════════════════════════════════════
#  Main exploit
# ══════════════════════════════════════════════

def exploit():
    log.info(f'Connecting to {HOST}:{PORT} …')
    r = remote(HOST, PORT)

    # ── Read banner ──────────────────────────────
    banner = r.recvuntil(b'Enter your vector: ', timeout=20).decode('utf-8', errors='replace')
    print(banner)

    iv_match  = re.search(r'IV:\s*([0-9a-f]+)',         banner)
    ct_match  = re.search(r'Ciphertext:\s*([0-9a-f]+)', banner)
    if not iv_match or not ct_match:
        log.error('Could not parse IV / Ciphertext'); r.close(); return
    iv_hex = iv_match.group(1)
    ct_hex = ct_match.group(1)
    log.success(f'IV         : {iv_hex}')
    log.success(f'Ciphertext : {ct_hex}')

    trusted = parse_trusted_from_banner(banner)
    if not trusted:
        log.error('Could not parse trusted vectors'); r.close(); return
    log.info(f'Parsed {len(trusted)} trusted vectors:')
    for i,(v,h) in enumerate(trusted):
        log.info(f'  v{i+1}: len={len(v):2d}  {v[:4]}{"…" if len(v)>4 else ""}')

    # ── Pick the shortest trusted vector as base ─
    trusted.sort(key=lambda x: len(x[0]))
    base_vec, base_hash = trusted[0]
    base_len = len(base_vec)
    log.info(f'Base vector length: {base_len}')

    # ── Step 1: query all trusted vectors ────────
    log.info('Querying all trusted vectors for initial dot products…')
    trusted_with_dots = []
    for vec, h in trusted:
        dp = do_query(r, str(vec), h)
        if dp is not None:
            trusted_with_dots.append((vec, h, dp))
            log.info(f'  len={len(vec):2d}  dot={dp}')
        else:
            log.warning(f'  len={len(vec):2d}  FAILED')

    # base dot product
    base_dot = next((dp for v,h,dp in trusted_with_dots if v == base_vec), None)
    if base_dot is None:
        log.error('Base query failed!'); r.close(); return

    # ── Step 2: length-extension to get key[base_len .. 31] ──
    log.info(f'Extracting key bytes [{base_len}..{KEY_SIZE-1}] via length extension…')
    key = [None] * KEY_SIZE

    for i in range(base_len, KEY_SIZE):
        ext_str  = ',0' * (i - base_len) + ',1'
        send_str, fhash, parsed_vec = make_forged_query(base_vec, base_hash, ext_str)

        if parsed_vec is None:
            log.warning(f'  key[{i}]: forge failed'); continue

        dp = do_query(r, send_str, fhash)
        if dp is None:
            log.warning(f'  key[{i}]: query failed'); continue

        key[i] = dp - base_dot
        log.info(f'  key[{i:2d}] = {key[i]}')

    # ── Step 3: solve for key[0 .. base_len-1] ───
    log.info(f'Solving linear system for key bytes [0..{base_len-1}]…')

    A_rows, b_rows = [], []
    for vec, h, dp in trusted_with_dots:
        n       = len(vec)
        abs_v   = [abs(x) for x in vec]
        rhs     = dp
        # subtract contribution from already-known positions
        for j in range(base_len, min(n, KEY_SIZE)):
            if key[j] is not None:
                rhs -= abs_v[j] * key[j]
        coeffs  = [abs_v[j] if j < n else 0 for j in range(base_len)]
        A_rows.append(coeffs)
        b_rows.append(rhs)

    A = np.array(A_rows, dtype=float)
    b = np.array(b_rows,  dtype=float)
    log.info(f'  System: {A.shape[0]} eqs × {A.shape[1]} unknowns  (rank {int(np.linalg.matrix_rank(A))})')

    sol, _, _, _ = np.linalg.lstsq(A, b, rcond=None)
    sol_int = [round(x) for x in sol]
    log.info(f'  Inner bytes solution: {sol_int}')


    # Validate: all bytes must be in [0, 255]
    if all(0 <= x <= 255 for x in sol_int):
        for i in range(base_len):
            key[i] = sol_int[i]
        log.success('Linear system solved cleanly ✓')
    else:
        log.warning('Solution has out-of-range bytes – clamping and hoping for the best')
        for i in range(base_len):
            key[i] = max(0, min(255, sol_int[i]))

    # ── Step 4: decrypt ───────────────────────────
    log.info('Attempting AES-CBC decryption…')
    final_key = [k if (k is not None) else 0 for k in key]
    log.info(f'Key: {final_key}')

    flag = try_decrypt(final_key, iv_hex, ct_hex)
    if flag:
        log.success(f'\n\n  FLAG → {flag}\n')
    else:
        log.warning('Decryption failed with recovered key.')

        # Brute-force any None positions (should be rare)
        import itertools
        unknowns = [i for i in range(KEY_SIZE) if key[i] is None]
        if unknowns and len(unknowns) <= 2:
            log.info(f'Brute-forcing {len(unknowns)} remaining unknown(s)…')
            for cand in itertools.product(range(256), repeat=len(unknowns)):
                test = final_key[:]
                for idx, val in zip(unknowns, cand):
                    test[idx] = val
                flag = try_decrypt(test, iv_hex, ct_hex)
                if flag:
                    log.success(f'\n\n  FLAG → {flag}\n')
                    break
            else:
                log.error('Brute-force exhausted without finding flag.')

    r.close()


if __name__ == '__main__':
    exploit()