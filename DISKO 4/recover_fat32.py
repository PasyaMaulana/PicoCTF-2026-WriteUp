#!/usr/bin/env python3
"""
CTF Solve: FAT32 Deleted File Recovery
=======================================
File dihapus dari FAT32 disk image
-> FAT32 hanya hapus entri direktori (byte pertama = 0xE5)
-> Data di cluster MASIH ADA sampai ditimpa
-> Kita scan cluster, temukan file terhapus, decompress, dapat flag

Cara pakai:
    python recover_fat32.py disko-4_dd
"""

import struct, gzip, re, sys

disk_path = sys.argv[1] if len(sys.argv) > 1 else 'disko-4_dd'
data = open(disk_path, 'rb').read()
print(f"[*] Disk size: {len(data)} bytes")

# =====================
# Parse FAT32 Boot Sector
# =====================
bs = data[:512]
bytes_per_sector  = struct.unpack_from('<H', bs, 11)[0]
sectors_per_cluster = struct.unpack_from('<B', bs, 13)[0]
reserved_sectors  = struct.unpack_from('<H', bs, 14)[0]
num_fats          = struct.unpack_from('<B', bs, 16)[0]
fat_size          = struct.unpack_from('<I', bs, 36)[0]
root_cluster      = struct.unpack_from('<I', bs, 44)[0]

cluster_size = bytes_per_sector * sectors_per_cluster
fat_start    = reserved_sectors * bytes_per_sector
data_start   = (reserved_sectors + num_fats * fat_size) * bytes_per_sector

print(f"[*] Cluster size : {cluster_size} bytes")
print(f"[*] FAT start    : {fat_start:#x}")
print(f"[*] Data start   : {data_start:#x}")
print(f"[*] Root cluster : {root_cluster}")

def cluster_offset(c):
    return data_start + (c - 2) * cluster_size

def get_fat(c):
    return struct.unpack_from('<I', data, fat_start + c * 4)[0] & 0x0FFFFFFF

# =====================
# Scan All Directories (iterative)
# =====================
def scan_dirs(root):
    queue = [(root, "")]
    visited = set()
    entries = []

    while queue:
        cluster, path = queue.pop()
        if cluster in visited:
            continue
        visited.add(cluster)

        cur = cluster
        seen = set()
        while cur not in seen and 2 <= cur < 0x0FFFFFF8:
            seen.add(cur)
            off = cluster_offset(cur)

            for i in range(0, cluster_size, 32):
                entry = data[off + i: off + i + 32]
                if entry == b'\x00' * 32:
                    continue
                first = entry[0]
                attr  = entry[11]

                if attr == 0x0F:   # Long File Name entry, skip
                    continue
                if first == 0x00:  # End of directory
                    break

                deleted = (first == 0xE5)
                name = entry[0:8].decode('ascii', 'replace').strip()
                ext  = entry[8:11].decode('ascii', 'replace').strip()
                size = struct.unpack_from('<I', entry, 28)[0]
                fclus = (struct.unpack_from('<H', entry, 20)[0] << 16) | \
                         struct.unpack_from('<H', entry, 26)[0]

                fname = (name + ('.' + ext if ext else '')).strip()
                if fname in ('.', '..'):
                    continue

                fullpath = path + fname
                status   = "DELETED" if deleted else "active"
                entries.append((status, fullpath, size, fclus))

                # Queue subdirectory
                if (attr & 0x10) and not deleted and fclus >= 2:
                    queue.append((fclus, fullpath + "/"))

            cur = get_fat(cur)

    return entries

print("\n[*] Scanning directories...")
entries = scan_dirs(root_cluster)
print(f"[*] Found {len(entries)} entries\n")

# =====================
# Show & Recover Deleted Files
# =====================
print("=== Deleted Files ===")
for status, name, size, clus in entries:
    if status != "DELETED":
        continue
    print(f"  [DEL] {name}  size={size}  cluster={clus}")

    if clus < 2:
        continue
    off     = cluster_offset(clus)
    content = data[off: off + max(size, 512)]

    # Try to decompress if gzip
    if content[:2] == b'\x1f\x8b':
        try:
            decompressed = gzip.decompress(content[:size] if size else content)
            print(f"    [gzip] Decompressed: {decompressed[:300]}")
            flags = re.findall(rb'picoCTF\{[^}]+\}', decompressed)
            if flags:
                print(f"\n  *** FLAG: {flags[0].decode()} ***\n")
        except Exception as e:
            print(f"    [gzip error] {e}")
    else:
        preview = content[:100]
        if preview.strip(b'\x00\xff'):
            print(f"    Preview: {preview}")

        flags = re.findall(rb'picoCTF\{[^}]+\}', content)
        if flags:
            print(f"\n  *** FLAG: {flags[0].decode()} ***\n")

# =====================
# Bonus: brute scan whole disk for flag
# =====================
print("\n[*] Brute scanning disk for picoCTF flag pattern...")
flags = re.findall(rb'picoCTF\{[^}]+\}', data)
if flags:
    for f in set(flags):
        print(f"  FOUND: {f.decode()}")
else:
    print("  Not found via brute scan")

