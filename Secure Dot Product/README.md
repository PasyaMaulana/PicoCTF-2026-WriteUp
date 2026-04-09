# Secure Dot Product — picoCTF 2026 Writeup

**Category:** Cryptography  
**Challenge:** Secure Dot Product  
**Event:** picoCTF 2026

---

## Deskripsi Soal

Server menyimpan sebuah **secret key** (32 byte) dan mengenkripsi flag dengan **AES-CBC** menggunakan key tersebut. Kita bisa mengirim vektor dan server akan membalas dengan **dot product** antara vektor kita dan key. Namun ada proteksi berupa **SHA-512 hash** yang harus kita penuhi agar query diterima.

Tujuan: pulihkan semua 32 byte key, lalu decrypt flag.

---

## Vulnerabilitas

### 1. `parse_vector` Strips Tanda Negatif

Server membersihkan input vektor dengan menghapus karakter selain digit, koma, dan bracket — termasuk tanda `-`. Akibatnya, server selalu menghitung:

```
dot(abs(v), key)  ← bukan dot(v, key)
```

Ini berarti kita tidak bisa membedakan positif/negatif dari elemen vektor, tapi kita tetap bisa memanfaatkan struktur vektor untuk mengekstrak key.

### 2. SHA-512 Tanpa HMAC → Length Extension Attack

Server menggunakan:
```
hash = SHA-512(salt ‖ vector_content)
```

Karena tidak menggunakan HMAC, hash ini **rentan terhadap SHA-512 Length Extension Attack**. Kita bisa memalsukan hash untuk pesan yang diperpanjang (`message ‖ padding ‖ extension`) tanpa mengetahui salt.

---

## Strategi Exploit

### Step 1 — Query Semua Trusted Vector

Server memberikan beberapa **trusted vector** beserta hash-nya di banner awal. Kita query semuanya untuk mendapat:

```
dot(abs(v_i), key)  untuk setiap v_i
```

### Step 2 — Length Extension untuk Ekstrak Key Byte Per Byte

Ambil trusted vector terpendek sebagai base (`base_vec`, panjang `n`). Lakukan length extension untuk membuat vektor baru:

```
[base_vec..., 0, 0, ..., 1]  ← 1 di posisi ke-i
```

Hasilnya:
```
dot_extended = dot(base_vec, key) + key[i]
key[i] = dot_extended - base_dot
```

Ulangi untuk semua posisi `i` dari `n` hingga `31`.

### Step 3 — Selesaikan Sistem Linear untuk Key Byte Awal

Untuk key byte di posisi `0` hingga `n-1` (yang tidak bisa dijangkau oleh length extension), gunakan semua trusted vector untuk membentuk **sistem persamaan linear**:

```
abs(v1[0])*key[0] + abs(v1[1])*key[1] + ... = dot1 - (kontribusi posisi yang sudah diketahui)
abs(v2[0])*key[0] + abs(v2[1])*key[1] + ... = dot2 - ...
...
```

Selesaikan dengan **least squares** (`numpy.linalg.lstsq`) dan bulatkan hasilnya.

### Step 4 — Decrypt AES-CBC

Dengan key yang sudah terpulihkan, decrypt ciphertext:

```python
AES.new(key_bytes, AES.MODE_CBC, iv).decrypt(ciphertext)
```

---

## Cara Pakai

### Install Requirements

```bash
pip install pwntools pycryptodome numpy
```

### Jalankan Exploit

```bash
python3 exploit.py
```

Pastikan `HOST` dan `PORT` di bagian CONFIG sudah sesuai dengan instance challenge yang aktif.

---

## Contoh Output

```
[*] Connecting to lonely-island.picoctf.net:52393 …
[+] IV         : <hex>
[+] Ciphertext : <hex>
[*] Parsed 3 trusted vectors
[*] Base vector length: 8
[*] Querying all trusted vectors...
[*] Extracting key bytes [8..31] via length extension…
    key[ 8] = 142
    key[ 9] = 87
    ...
[*] Solving linear system for key bytes [0..7]…
[+] Linear system solved cleanly ✓
[*] Attempting AES-CBC decryption…
[+]   FLAG → picoCTF{...}
```

---

## Requirements

| Library | Fungsi |
|---|---|
| `pwntools` | Koneksi socket ke server |
| `pycryptodome` | AES-CBC decryption |
| `numpy` | Penyelesaian sistem linear (least squares) |
| `struct`, `re`, `ast` | Parsing binary dan teks (built-in) |

---

## Catatan

> ⚠️ SHA-512 length extension diimplementasikan secara manual (pure Python) tanpa library eksternal — tidak perlu `hashpumpy` atau tool tambahan.

> ℹ️ Jika sistem linear menghasilkan nilai di luar range `[0, 255]`, script otomatis melakukan clamping. Jika masih ada byte yang tidak diketahui (≤2), dilakukan brute-force.

> ℹ️ Exploit mungkin perlu dijalankan beberapa kali jika koneksi timeout atau server memberikan trusted vector yang kurang untuk membentuk sistem yang full rank.