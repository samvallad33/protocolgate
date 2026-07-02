# ProtocolGate

**Audits check the code. ProtocolGate checks the control plane around the code.**

[![CI](https://github.com/samvallad33/protocolgate/actions/workflows/protocolgate.yml/badge.svg)](https://github.com/samvallad33/protocolgate/actions/workflows/protocolgate.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Status: Alpha 0.1.0](https://img.shields.io/badge/status-alpha%200.1.0-orange.svg)](#status)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](#install)

The $1.5B Bybit hack wasn't a Solidity bug. The contracts were fine. The *signing flow* was compromised — approvers blind-signed a delegatecall that swapped the proxy out from under them. No audit catches that, because the code was never the problem.

ProtocolGate is a CLI + GitHub Action that gates the setup *around* your contracts: who admins the proxy, whether upgrades sit behind a timelock, whether your multisig is real or paper, and — most importantly — whether the calldata your signers approved is the calldata that actually executes. You declare your deployment topology in one file. The engine runs 34 rules against it. If anything fails, the build fails and the deploy is blocked.

> **Status:** Alpha (0.1.0). Not on PyPI yet — install from source with `uv`.

## Install

```bash
git clone https://github.com/samvallad33/protocolgate
cd protocolgate
uv run protocolgate --help
```

Every command runs through `uv run protocolgate <cmd>`. Python 3.11+.

## The one rule that maps to Bybit: CG034

The Bybit failure class is *signers approving one payload while a different one executes*. CG034 is the rule aimed at it. In your manifest you declare two hashes — the calldata your signers reviewed (`reviewed_calldata_hash`) and the calldata slated to execute (`execution_calldata_hash`). **CG034 fails `critical` if either is missing, malformed, or unequal**, turning "we're pretty sure it's the same transaction" into an assertion CI enforces.

Honest limit: ProtocolGate doesn't compute these hashes from real calldata — *you* supply them, so source the execution hash independently for the check to mean anything. That's the point of CG034: make the match a reviewable, build-blocking claim instead of a hope. It's the single most unique thing this tool does.

## Quickstart

```bash
# Validate a manifest — exits non-zero if any rule fails
uv run protocolgate validate protocolgate.yaml

# Try it on the bundled examples
uv run protocolgate validate examples/protocolgate.valid.yaml     # passes
uv run protocolgate validate examples/protocolgate.invalid.yaml   # fails, shows findings

# Compare a live snapshot against your manifest (drift detection)
uv run protocolgate drift protocolgate.yaml live-state.json
```

Output as `table` (default), `json`, or `markdown`.

## The one file

You describe your deployment — proxies, admins, timelocks, multisigs, oracles, bridges, treasury — in `protocolgate.yaml`. That's the whole interface. The engine reads it, runs the rules deterministically, and prints what's wrong and how to fix it. Findings carry a rule ID (`CGxxx`), a severity, the failing path, and remediation.

Real manifests to copy from:

- [`examples/protocolgate.valid.yaml`](examples/protocolgate.valid.yaml) — a clean setup
- [`examples/protocolgate.invalid.yaml`](examples/protocolgate.invalid.yaml) — deliberately broken
- [`examples/protocolgate.proposal-intent.yaml`](examples/protocolgate.proposal-intent.yaml) — the CG034 calldata gate
- [`examples/public/`](examples/public/) — real protocols: Aave Governance v3, Compound Comet USDC, Lido Core, DRE Labs dreUSD

## In CI

Drop this in a workflow to block any deploy PR that fails a rule:

```yaml
- uses: actions/checkout@v4
- uses: samvallad33/protocolgate/action@main
  with:
    manifest: protocolgate.yaml
```

Non-zero exit → red check → merge blocked. No servers, no accounts, no API keys.

## What it checks

The 34 rules (`CG001`–`CG026`, `CG032`–`CG039`) cover:

| Area | Example checks |
|------|----------------|
| **Admin control** | Proxy admin isn't an EOA; upgrade power sits behind a timelock |
| **Multisig** | No paper (1-of-N) multisigs |
| **Timelocks** | Delays enforced on admin, unpause, supply, and fee changes |
| **Oracles** | Staleness bounds are set |
| **Bridges** | Rate limits are declared |
| **Treasury** | Splits sum correctly |
| **Chain** | Chain ID is pinned |
| **Signing (CG034)** | Reviewed vs. executed calldata hashes (declared) match; selector + Safe-module allowlists |
| **Drift** | A live JSON snapshot matches the manifest you shipped |

Full list: [`policies/catalog.md`](policies/catalog.md).

## What it isn't

ProtocolGate earns trust by being honest about its edges:

- It checks the topology **you declare**. It's only as good as your manifest — lie in the file, pass the gate.
- CG034's hashes are inputs you provide, not values ProtocolGate computes from real calldata — it checks they're present, well-formed, and equal, not that either reflects the actual transaction.
- It does **not** replace audits, fuzzing, or runtime monitoring. It's a different layer.
- It does **not** (yet) query live RPC, fetch Safe transactions, or run simulations for you. You feed it the facts.
- The rule engine is the only decision-maker. No LLM, no heuristics, no network calls.

## Docs

- [Proposal Intent Gate (CG034)](docs/PROPOSAL_INTENT_GATE.md) — the calldata-match deep dive
- [Invariant Hunter](docs/INVARIANT_HUNTER.md) — the `CG039` hunt rule
- [Policy catalog](policies/catalog.md) — every rule, severity, and remediation

Optional: pairing with [Vestige](https://github.com/samvallad33/vestige) (AGPL-3.0) adds cross-engagement memory. It's entirely optional — ProtocolGate has no dependency on it.

## License

Apache-2.0. See [LICENSE](LICENSE).
