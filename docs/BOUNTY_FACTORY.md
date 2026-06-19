# ProtocolGate Bounty Factory

> Drift → Memory → Proof. The control-plane that nobody else has wired end to end.

This document is the source of truth for the bounty-factory build. It replaces
the earlier aspirational "5 novel concepts" framing with a code-grounded plan
based on what the repo actually does today (capability audit, 2026-06-19).

## The thesis

Code on mainnet does not change. **Permissions do.** Hunters audit a protocol at
launch, declare it safe, and stop looking. Six months later a team rotates a
multisig signer, shortens a timelock, or upgrades an implementation during a
routine admin change — and nobody is watching the authority layer anymore.

The factory's entire edge is catching that **drift** and proving it matters with
a fork test. Static fortresses (DeXe, SSV, Aave) pay $0 because nothing drifted.
Drift is where the money is, so the **collector is the moat**, not the glue.

## What already exists (reuse, do not rebuild)

`src/protocolgate/bounty_sim.py :: run_bounty_simulation()` already chains:

```
load manifest → compare_snapshot() → VerdictCapsule[] → generate Foundry project
  → forge test → (optional) write to Vestige via stdio smart_ingest → verdict
```

- **Drift detector** — `drift.py :: compare_snapshot(manifest, snapshot)`.
  Snapshot shape it consumes:
  `{contracts: [{name, proxy: {admin}}], multisigs: [{name, threshold}]}`.
- **Verdict capsules** — `capsules.py`, schema v1, sha256 ids, JSONL.
- **Verdict enum** — `pass_no_runtime_drift | open_door_machine_checked_needs_source_trace
  | open_door_needs_foundry_run | open_door_foundry_failed_needs_debug`.
- **Vestige write seam** — stdio `smart_ingest` (gated `--vestige-mcp`, default off).
- **Vestige read seam** — `memory.py :: VestigeClient.query()` → HTTP
  `localhost:3927/api/deep_reference`. Reusable as-is.

Entry point is `protocolgate bounty-sim <manifest> <snapshot>`, **not**
`protocolgate scan --json` (that verb does not exist).

## The two real gaps (this is the product)

1. **On-chain snapshot collector** — turns a target's deployed addresses into the
   `snapshot.json` the drift detector consumes, by reading live chain state:
   - proxy admin via EIP-1967 admin slot (`eth_getStorageAt`)
   - Safe threshold via `getThreshold()` (`eth_call`)
   Read-only. No keys. No mainnet transactions. This is `collector.py`.

2. **Real Foundry fork PoC** — today's harness asserts `sha256(expected) != sha256(actual)`,
   which only re-states the drift. A real PoC does `vm.createSelectFork(rpc, block)`,
   pulls forge-std, and asserts an **impact** (e.g. the drifted admin can call a
   protected upgrade path). Per-template, not generic.

## The bright line (never cross it)

A green `forge test` means **drift is reproducible**, not that a bounty exists.
The runner intentionally tops out at `needs-source-trace`. `submission-ready` is a
**manual** decision through `bounty-scope` (submit / defer / kill). The factory
never auto-promotes a finding to submittable.

Operating constraints: **fork tests only, no mainnet transactions, no private keys.**

## Architecture

```
targets.yaml (scope, payout, addresses, chain, rpc, manifest path)
   │
   ▼
collector.py ──(eth_getStorageAt / eth_call, read-only)──▶ snapshot.json
   │
   ▼
factory.py
   ├─ read-back: VestigeClient.query(lane_signature) ─ skip known dead doors
   ├─ run_bounty_simulation(manifest, snapshot, run_foundry, write_vestige)
   │     └─ compare_snapshot → capsules → Foundry fork PoC → forge test → verdict
   └─ outcome map → dead-door | needs-config | needs-PoC | submission-ready(manual)
   │
   ▼
capsules.jsonl  +  Vestige (closed doors persist so tomorrow is faster)
```

## Build order

- **(a) Factory loop + read-back bridge + fixtures** — composes tested pieces. This week.
- **(b) Collector spike** — the moat. RPC → snapshot.json.
- **(c) Real fork PoC generator** — 3 templates: `proxy_admin_drift`,
  `timelock_bypass_or_role_drift`, `oracle_config_drift`.
- **(d) Forensic autopsy** — diff snapshots across blocks/time, attribute *when* a
  control-plane value changed. Thin layer over timestamped capsules. The one
  genuinely novel keeper.

## The 5 "novel concepts" — honest disposition

| Concept | Disposition | Why |
|---|---|---|
| Chronological forensic autopsy | **KEEP** (step d) | Thin layer over timestamped capsules; real bounty value |
| Control-plane mutation testing | **MERGE into (c)** | It *is* the fork PoC generator under another name |
| Griefing / economic sim | **DEFER** | Needs a working fork PoC first |
| Cross-chain topology homology | **CUT** | Research project; repo has zero cross-chain modeling |
| Memory-induced state fuzzing | **CUT** | Composes two things that don't exist; hype, not architecture |
