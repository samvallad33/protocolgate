# ProtocolGate v0.1.0 — Control-plane policy gate (Alpha)

> Audits check the code. ProtocolGate checks the control plane around the code.

ProtocolGate is an open-source, **deterministic** policy gate for the
smart-contract **control plane**. Declare your deployment's authority topology in
a manifest — proxy admins, multisig thresholds, timelock delays, treasury splits,
oracle staleness, bridge limits, pause/upgrade separation, proposal-to-calldata
binding — and gate it **in CI, before you deploy**.

Most big 2026 losses weren't Solidity bugs — they were operational: an admin key
with no timelock (Drift, ~$285M), a single bridge verifier (KelpDAO, ~$292M), a
signing flow that showed one thing and executed another (Bybit, ~$1.5B). The
contracts did exactly what they were written to do. The money left through the
control plane. This is the layer OpenZeppelin Defender's shutdown just orphaned.

## What's in 0.1.0
- **Deterministic rule engine:** CG001–CG026, CG032–CG038, plus the CG039 hunt rule
- **CLI:** `validate`, `hunt`, `drift`, `bounty-scope`, `export-input`
- **GitHub Action** for CI gating (exit non-zero blocks the deploy)
- **Verdict capsules** + optional advisory **Vestige** memory client
- **Public case-study fixtures** (Aave v3 governance, Compound Comet, Lido) —
  clearly-labeled synthetic demos, **not audits**
- Experimental OPA/Rego policy subset

## Honest scope
- **Alpha (0.1.0)** — interfaces may change before 1.0.
- Deterministic: **no LLM** in the pass/fail path; a finding is reproducible from
  the manifest alone.
- Does **not** replace a source-code audit, formal verification, or live
  monitoring, and **cannot stop a compromised signer** — it flags the
  control-plane conditions (EOA admins, missing timelocks, paper multisigs) that
  turn one bad signature into a total loss.
- Not yet on PyPI — install from source.

## Quickstart
```bash
git clone https://github.com/samvallad33/protocolgate
cd protocolgate
uv run protocolgate validate examples/protocolgate.valid.yaml
uv run protocolgate validate examples/protocolgate.invalid.yaml --output json
```

**License:** Apache-2.0
