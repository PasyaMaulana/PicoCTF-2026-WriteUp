# Not TRUe — picoCTF 2026 Writeup

**Category:** Cryptography  
**Challenge:** Not TRUe  
**Event:** picoCTF 2026

---

## Deskripsi Soal

Server menggunakan skema kriptografi **NTRU** (Number Theory Research Unit) untuk mengenkripsi flag. Kita diberikan parameter publik berupa:

- `N = 48` — derajat polinomial
- `p = 3`, `q = 509` — moduli kecil dan besar
- `h` — public key (polinomial berderajat N)
- `ct` — array ciphertext (beberapa blok terenkripsi)

Tujuan: pulihkan **private key** `f` dari public key `h`, lalu dekripsi semua blok ciphertext untuk mendapatkan flag.

---

## Vulnerabilitas

### 1. Parameter N Terlalu Kecil

NTRU aman jika `N` cukup besar (umumnya N ≥ 401). Dengan `N = 48`, dimensi lattice hanya **96×96**, sehingga reduksi **LLL** dapat menemukan private key dalam hitungan detik.

### 2. Struktur Lattice NTRU Bocorkan Private Key

Public key NTRU didefinisikan sebagai:

```
h ≡ f_inv * g (mod q)
```

Ini membentuk lattice 2D berstruktur siklik yang dapat dikonstruksi:

```
M = | I   H |
    | 0   qI |
```

Di mana `H` adalah matriks sirkulan dari `h`. Vektor pendek `(f, g)` tersembunyi di dalam lattice ini, dan LLL dapat menemukannya karena norma `f` dan `g` kecil relatif terhadap `q`.

---

## Strategi Exploit

### Step 1 — Bangun Matriks Lattice 2N × 2N

Konstruksi matriks lattice berukuran `2N × 2N` dengan blok sirkulan dari `h`:

```python
M = Matrix(ZZ, 2*N, 2*N)
for i in range(N):
    M[i, i] = 1
    for j in range(N):
        M[i, N + j] = h[(j - i) % N]   # baris sirkulan dari h
    M[N + i, N + i] = q
```

### Step 2 — Reduksi LLL

Jalankan algoritma LLL pada matriks lattice untuk menemukan basis pendek:

```python
L = M.LLL()
```

Karena `N = 48`, proses ini selesai sangat cepat. Baris-baris pendek dari `L` merupakan kandidat private key `f` (dan `g`).

### Step 3 — Validasi Kandidat f

Untuk setiap baris hasil LLL, ambil `N` koefisien pertama sebagai kandidat `f`, lalu cek apakah ia **invertible modulo p**:

```python
for row in L:
    f_cand = list(row[:N])
    f_p_inv = R_modp(f_cand)**-1   # jika exception → bukan f yang benar
```

### Step 4 — Dekripsi Ciphertext

Dengan `f` yang valid, dekripsi setiap blok ciphertext menggunakan prosedur standar NTRU:

```
a  = f * c      (mod q)         ← perkalian di ring Z[x]/(x^N - 1)
a' = center_lift(a, q)          ← angkat ke bilangan bulat, rentang [-q/2, q/2]
m  = f_inv * a' (mod p)         ← dekripsi pesan di ring mod p
```

### Step 5 — Rekonstruksi Flag

Setiap blok pesan `m` adalah polinomial berkoefisien bit `{0, 1, 2}` (mod 3). Koefisien dikoncatenasi sebagai bit biner, lalu dikonversi ke ASCII:

```python
binary_str += ''.join(str(b) for b in m_bits)
flag = ''.join(chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8))
```

---

## Cara Pakai

### Install Requirements

```bash
pip install sage  # atau gunakan SageMath langsung
```

### Jalankan Exploit

```bash
sage exploit.sage
# atau
python3 exploit.py  # jika menggunakan sage.all via Python
```

---

## Contoh Output

```
[*] Membangun Matriks Lattice...
[*] Menjalankan reduksi LLL (Ini akan sangat cepat karena N kecil)...
[+] Flag berhasil ditemukan:

picoCTF{...}
```

---

## Requirements

| Library | Fungsi |
|---|---|
| `sage` / `sage.all` | Operasi ring polinomial, matriks lattice, dan LLL |
| `PolynomialRing(ZZ)` | Ring polinomial atas bilangan bulat |
| `Matrix(ZZ)` | Konstruksi matriks lattice |
| `M.LLL()` | Reduksi basis lattice (built-in SageMath) |

---

## Catatan

> ⚠️ Exploit ini hanya bekerja karena `N = 48` sangat kecil. Pada implementasi NTRU nyata dengan `N ≥ 401`, reduksi LLL tidak praktis secara komputasi.

> ℹ️ Fungsi `center_lift` penting untuk memastikan koefisien berada di rentang `[-q/2, q/2]` sebelum reduksi mod `p`. Tanpa ini, dekripsi akan menghasilkan nilai yang salah.

> ℹ️ Jika semua baris LLL gagal divalidasi, coba negasikan kandidat `f` (kalikan dengan `-1`) — LLL kadang mengembalikan vektor dengan tanda terbalik.
