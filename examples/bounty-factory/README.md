# Bounty Factory

The bounty factory turns a list of protocols into a triaged worklist. For each
target it collects live control-plane state, asks institutional memory whether a
lane is already dead, runs deterministic drift comparison, and maps the target to
one of four states. It is the read-only front of the
`drift -> memory -> proof` loop.

## The drift -> memory -> proof loop

1. **Collect (live state).** The read-only collector reads each contract's
   EIP-1967 proxy-admin slot (`eth_getStorageAt`) and each Safe's
   `getThreshold()` (`eth_call`) over a standard JSON-RPC endpoint, and emits a
   `snapshot.json` in the exact shape `drift` consumes. No private keys, no
   transactions, no signing — only `eth_getStorageAt` and `eth_call`.

2. **Drift (deterministic signal).** `drift` compares the declared manifest
   (expected admin / threshold) against the collected snapshot. A drifted proxy
   admin is `critical`; a missing one is `high`; a changed multisig threshold is
   `high`; a missing object is `medium`. No drift relative to live state means
   the target pays $0 — the live snapshot is the moat.

3. **Memory (closed-door read-back, BEFORE deep work).** Before spending effort,
   the factory builds a signature per prospective lane (`target:subject:kind`)
   and queries your local Vestige memory server. If a prior capsule marked that
   lane dead (markers like `dead-door`, `closed-door`, `reopen_if`), the lane is
   skipped instead of re-hunted. If Vestige is unavailable, read-back degrades to
   "not queried" — never fatal.

4. **Proof (machine-checkable, fork-only).** `bounty-sim` converts each live
   drift into a verdict capsule, generates a focused Foundry harness, and runs
   `forge test` to prove the drift signal is machine-checkable. This proves the
   signal reproduces; it does not by itself claim a bounty-ready exploit.

## States and the bright line

The factory maps each target to exactly one state:

| State              | Meaning                                                            |
| ------------------ | ----------------------------------------------------------------- |
| `dead-door`        | No live drift, or every lane was read-back-killed. Pays $0.        |
| `needs-config`     | An object is missing from the snapshot — likely collector noise or topology mismatch; re-collect at a pinned block. |
| `needs-PoC`        | Real, machine-checkable live drift. Needs a human source-trace and a fork PoC. |
| `submission-ready` | **NEVER assigned by the factory.** Human-only promotion.          |

**BRIGHT LINE:** the factory never auto-promotes to `submission-ready`. It tops
out at `needs-PoC` / needs-source-trace. Promotion is a human decision made
outside this loop with a real fork PoC, a scope review, and an impact trace.
Everything the factory runs is read-only and fork-only: no keys, no mainnet
transactions.

## Setup

