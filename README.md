# PoC for Bull.family bug bounty report B-18

## SDK `lock()`: beneficiary checked only after the transaction is mined — server locks the user's tokens for the attacker, who claims them in full

**Report B-18** (K-364). SDK under test: `sdk-live.mjs` — the NEW Bull SDK
live 18 Nov 2026, sha256 `220d326f…`, 26,232 bytes
(`https://www.bull.family/sdk/bull.mjs`).

### The bug

The SDK states: *"Safety: the API server is not trusted with your wallet.
Every transaction it returns is checked before it is sent."* The 18 Nov
patch added a schedule check to `lock()` (cliff/end/step within an hour)
— but the beneficiary, like the schedule, is only checked POST-tx,
against the last receipt. Locker steps are not decoded at all: `lock()`
passes no `fn`/`id`/`check` to the guard.

A compromised/malicious API server, against a victim who calls
`lock({token, amount: 100,000, beneficiary: victim, ...})`, returns a
`createLock` step naming the ATTACKER as beneficiary (100,000 tokens,
cliff now + window). The step is sent with no pre-send check of the
beneficiary. The lock is created for the attacker. `lock()`'s post-tx
check throws ("the lock that was created does not match what you asked
for") — but the lock already exists on-chain, and the attacker claims the
full 100,000 after the window. Victim wallet left 0.

**Measured (fresh Anvil):** lock #2: beneficiary = attacker, 100,000
tokens, claimed in full after the window; victim balance after: 0.

### Why this is not a duplicate

**B-13** (report `532575210b`) was the SCHEDULE tamper (cliff +10 years,
end +100 years) that passed SILENTLY — the SDK returned a lockId with no
error. This is a different field (beneficiary, not schedule) with a
different visibility (the SDK DOES throw — but only after the irreversible
transaction is mined, and the lock persists for the attacker). Different
mechanism, different fix (decode + verify the beneficiary pre-send).

### Threat model (stated honestly)

This requires the Bull API server to be compromised or malicious. That is
the SDK's own documented threat model ("the API server is not trusted").
The attacker needs no victim private key and no victim action beyond a
normal `lock()` call. No server compromise is demonstrated; the claim is
the SDK fails its own stated safety goal.

### Reproduce

Local Anvil only (chain 4663), mock malicious API, real NEW SDK verbatim,
live Agreement bytecode etched, mock locker. No real funds, no mainnet, no
Bull infrastructure. Throwaway local (Anvil default) keys only.

```bash
# terminal 1
anvil --port 8547 --chain-id 4663

# terminal 2
npm install            # installs viem
node run-poc.mjs       # 8 cases; relevant case: "K-364 lock() wrong-beneficiary"

# forge tests (live Agreement bytecode)
cd chain && forge test # relevant: testK364LockWrongBeneficiary
```

Expected runner output for the case: `EXPLOITED: true` — SDK sent the
step, then threw POST-tx; lock #2 exists for the attacker (100,000
tokens), claimable in full after the window.

### Files

- `run-poc.mjs` — node runner (mock API + real SDK + fresh Anvil)
- `sdk-live.mjs` — verbatim copy of the NEW live SDK (18 Nov 2026)
- `poc-result.json` — full round-9 results (all 5 PASS cases + negatives)
- `chain/` — Foundry tests on live Agreement/Escrow/Burner bytecode
  (`test/Round9A.t.sol`, `bytecode/`, `src/Mocks.sol`)

### Suggested fix

In `lock()`, decode the `createLock` calldata BEFORE sending and verify
token/amount/beneficiary/schedule against the caller's request — do not
rely on the post-tx receipt check, which runs after the irreversible lock
is already on-chain.
