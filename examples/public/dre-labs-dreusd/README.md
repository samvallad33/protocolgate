# dreUSD control-plane example (ProtocolGate demo)

A real, end-to-end example of ProtocolGate's deterministic policy gate plus the
optional Vestige institutional-memory layer, modeled on the public control-plane
topology of the DRE App dreUSD stablecoin (Base mainnet, Sherlock contest #1259).

## What is in here

- `protocolgate.dreusd.yaml` - an expected-policy manifest for dreUSD built from
  public contest metadata: 48h governance timelock, multisig topology, oracle
  staleness assumptions, LayerZero bridge rate limits, and a `proposal_intent`
  policy (calldata hash binding, 24h proposal validity, simulation + monitor
  requirements for supply-control changes).
- One **synthetic demo proposal** (`PG-DEMO-MINTCAP-001`, clearly labeled in the
  manifest): a "routine" daily-mint-cap increase whose execution calldata does
  not match what signers reviewed, with no simulation and no monitor coverage.
- `run_demo.sh` - runs the real CLI against the real manifest. Nothing is
  hardcoded or simulated in the output.

## Run it

```bash
./run_demo.sh                # deterministic gate + advisory memory (if running)
./run_demo.sh --no-memory    # deterministic gate only
```

Expected deterministic findings:

| Rule | Severity | What it catches |
| --- | --- | --- |
| CG034 | critical | execution calldata hash does not match the reviewed hash signers approved |
| CG037 | high | no passed transaction simulation for a supply-control proposal |
| CG038 | medium | no monitor coverage declared for a `mint_cap_change` action |

Exit code is non-zero: the gate rejects the proposal. This decision is made
entirely by the deterministic rule engine - no AI is involved in the verdict.

## The memory layer (advisory)

With a local Vestige memory server running, add `--with-memory` (the runner
does this by default):

```bash
uv run protocolgate validate examples/public/dre-labs-dreusd/protocolgate.dreusd.yaml --with-memory
```

Each finding gains an `Institutional Evidence (advisory)` block: trust-scored
memories retrieved from the team's own corpus - audit notes, review Q&A facts,
and operational decisions - with provenance. Example: a CG034 calldata mismatch
on `setDailyFiatMintCap` can surface the documented daily cap and any standing
change-freeze decisions, so a human reviewer sees *why* this proposal
contradicts recorded intent.

Two hard rules keep this honest:

1. **Memory never gates.** The exit code and findings are identical with or
   without `--with-memory`. If Vestige is down, the gate runs unaffected.
2. **Evidence is labeled.** Every memory line carries its trust score, date,
   and source. Demo-seeded items are tagged `simulated:demo` at ingest.

## Scope note

This manifest models DRE's publicly documented control-plane topology as an
expected-policy baseline. Findings against it are policy-model gaps, not
confirmed vulnerabilities in the deployed protocol.
