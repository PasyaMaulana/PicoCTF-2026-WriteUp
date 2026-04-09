# DISKO-4 — picoCTF 2026 Writeup

**Category:** Forensics  
**Challenge:** DISKO-4  
**Event:** picoCTF 2026

---

## Deskripsi Soal

Diberikan sebuah **FAT32 disk image** (`disko-4_dd`). Terdapat file yang telah dihapus di dalamnya. Tugas kita adalah memulihkan file tersebut dan menemukan flag.

---

## Konsep Utama

FAT32 **tidak langsung menghapus data** saat file dihapus. Yang terjadi hanyalah:

- Byte pertama nama file di direktori entry diubah menjadi `0xE5` (tanda "deleted")
- Data di cluster **tetap ada** sampai ditimpa oleh file lain

Artinya, kita bisa membaca langsung dari cluster yang direferensikan oleh entri yang sudah dihapus tersebut.

---

## Langkah Solve

### 1. Parse Boot Sector FAT32

Boot sector (512 byte pertama) menyimpan semua metadata penting:

| Field | Offset | Keterangan |
|---|---|---|
| Bytes per sector | 11 | Biasanya 512 |
| Sectors per cluster | 13 | Ukuran satu cluster |
| Reserved sectors | 14 | Letak FAT dimulai |
| Number of FATs | 16 | Biasanya 2 |
| FAT size (sectors) | 36 | Ukuran satu FAT |
| Root cluster | 44 | Cluster pertama direktori root |

Dari sini kita bisa menghitung:
- `cluster_size = bytes_per_sector × sectors_per_cluster`
- `fat_start = reserved_sectors × bytes_per_sector`
- `data_start = (reserved_sectors + num_fats × fat_size) × bytes_per_sector`

### 2. Scan Direktori

Iterasi semua cluster direktori secara rekursif (iterative BFS). Setiap entri direktori berukuran **32 byte**. Cek:

- `entry[0] == 0xE5` → file **dihapus** ✅
- `entry[0] == 0x00` → akhir direktori
- `entry[11] == 0x0F` → Long File Name (LFN), skip

Dari tiap entri kita ambil:
- Nama file + ekstensi (offset 0–10)
- Cluster awal (offset 20 + 26, digabung 32-bit)
- Ukuran file (offset 28)

### 3. Baca Data dari Cluster

```
offset = data_start + (cluster - 2) × cluster_size
```

Baca sejumlah `size` byte dari offset tersebut.

### 4. Decompress jika Gzip

Cek magic bytes pertama:
- `\x1f\x8b` → ini file **gzip** → decompress dengan `gzip.decompress()`

### 5. Cari Flag

Scan hasil decompress (atau raw content) untuk pattern:
```
picoCTF{...}
```

Sebagai fallback, lakukan **brute scan seluruh disk image** untuk pattern yang sama.

---

## Cara Pakai Script

```bash
python recover_fat32.py disko-4_dd
```

Jika nama file disk image berbeda:
```bash
python recover_fat32.py <nama_file_disk_image>
```

---

## Contoh Output

```
[*] Disk size: XXXXXX bytes
[*] Cluster size : 512 bytes
[*] FAT start    : 0x200
[*] Data start   : 0x4200
[*] Root cluster : 2

[*] Scanning directories...
[*] Found N entries

=== Deleted Files ===
  [DEL] FLAG.GZ  size=128  cluster=5
    [gzip] Decompressed: b'picoCTF{...}'

  *** FLAG: picoCTF{...} ***

[*] Brute scanning disk for picoCTF flag pattern...
  FOUND: picoCTF{...}
```

---

## Requirements

Python 3.x — tidak perlu install library eksternal, semua sudah built-in:

```
struct   → parsing binary data
gzip     → dekompresi file gzip
re       → regex pencarian flag
sys      → argumen command line
```

---

## Catatan

> ⚠️ Script mengasumsikan cluster pointer pada entri yang dihapus masih valid. Jika cluster sudah ditimpa data lain setelah penghapusan, recovery bisa gagal.

> ℹ️ Jika brute scan menemukan flag tapi recovery direktori tidak, kemungkinan entri direktori sudah corrupt tapi data di cluster masih utuh.