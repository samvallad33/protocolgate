# ProtocolGate

[![CI](https://github.com/samvallad33/protocolgate/actions/workflows/protocolgate.yml/badge.svg)](https://github.com/samvallad33/protocolgate/actions/workflows/protocolgate.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Status: Alpha 0.1.0](https://img.shields.io/badge/status-alpha%200.1.0-orange.svg)](#status)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

**Audits check the code. ProtocolGate checks the control plane around the code.**

The $1.5B Bybit exploit was not a Solidity bug. The contracts functioned perfectly. The critical failure occurred within the signing flow: approvers blind-signed a `delegatecall` transaction that swapped the underlying proxy implementation out from under them. Traditional smart contract audits fail to catch these vectors because the on-chain code itself is not the source of the vulnerability.

ProtocolGate is a lightweight CLI and GitHub Action designed to gate the entire operational setup surrounding your smart contracts. It enforces strict policies regarding proxy administration, timelock constraints, multisig thresholds, and critical execution calldata verification.

By declaring your deployment topology in a single declarative file, the static engine evaluates your architecture against 34 deterministic security policies before production deployment. If any security invariant is violated, the build fails and the deployment pipeline is immediately blocked.

> <a name="status"></a>**Status:** Alpha (0.1.0). Building directly from source via `uv` is required while packages are finalized.

## Installation

```bash
git clone https://github.com/samvallad33/protocolgate
cd protocolgate
uv run protocolgate --help
```

Requires Python 3.11 or higher. All terminal commands execute via the `uv` runner.

## Core Mitigation: Rule CG034 (The Bybit Fix)

The blind-signing vector involves signers reviewing and approving a specific payload while a mutated transaction executes on-chain. Rule CG034 targets this attack surface directly.

In your topology manifest, you declare two distinct cryptographic markers: the `reviewed_calldata_hash` and the `execution_calldata_hash`. The CG034 policy triggers a critical build failure if either hash is missing, structurally malformed, or if they do not match identically. This transforms loose operational assumptions into a strict assertion enforced directly by your deployment pipeline.

**Operational boundary.** ProtocolGate does not dynamically compute these hashes from live runtime calldata. You supply these inputs within the manifest. To maximize the utility of CG034, you must source the execution hash independently from your signing environment. This design choice forces the transactional match to become a transparent, build-blocking assertion instead of an operational hope.

## Quickstart

```bash
# Validate a local manifest configuration (exits non-zero on policy failure)
uv run protocolgate validate protocolgate.yaml

# Evaluate bundled test configurations
uv run protocolgate validate examples/protocolgate.valid.yaml     # pass
uv run protocolgate validate examples/protocolgate.invalid.yaml   # fail (returns structural findings)

# Compare a live network snapshot against your manifest for drift detection
uv run protocolgate drift protocolgate.yaml live-state.json
```

Output formatting is available as standard stdout tables (default), raw JSON, or Markdown via `--output`.

## The Topology Manifest File

Your entire deployment infrastructure topology is described inside a single `protocolgate.yaml` configuration file. This manifest maps the intended relationships between proxies, administrators, timelocks, multisigs, oracles, cross-chain bridges, and treasuries.

The engine processes this file, runs the rules deterministically, and isolates errors. Every generated finding returns an explicit rule identifier (`CGxxx`), an assigned severity tier, the specific failing configuration path, and exact remediation instructions.

Reference configurations available in the repository:

- [`examples/protocolgate.valid.yaml`](examples/protocolgate.valid.yaml) — production-grade reference setup
- [`examples/protocolgate.invalid.yaml`](examples/protocolgate.invalid.yaml) — deliberately broken configuration showcasing error findings
- [`examples/protocolgate.proposal-intent.yaml`](examples/protocolgate.proposal-intent.yaml) — configuration for the CG034 calldata gate
- [`examples/public/`](examples/public/) — manifests modeled from live Web3 protocols: Aave Governance v3, Compound Comet USDC, Lido Core, and DRE Labs dreUSD

## Continuous Integration (CI/CD)

Drop ProtocolGate directly into your existing deployment workflows to block insecure pull requests before they merge:

```yaml
- uses: actions/checkout@v4
- uses: samvallad33/protocolgate/action@main
  with:
    manifest: protocolgate.yaml
```

A non-zero exit code stops the pipeline, applies a red check to the pull request, and blocks deployment. This execution model runs entirely locally in the runner environment: no external servers, no cloud accounts, and no third-party API keys.

## Policy Coverage

The 34 built-in rules (`CG001` through `CG026`, and `CG032` through `CG039`) evaluate the following infrastructure vectors:

| Security Focus Area | Evaluated Invariants and Policy Checks |
| --- | --- |
| **Admin Control** | Ensures proxy admins are smart contracts rather than EOAs; verifies upgrade authority is isolated behind a timelock contract. |
| **Multisig Hygiene** | Flags paper configurations, such as low-threshold 1-of-N signing requirements. |
| **Timelock Enforcement** | Enforces minimum delays on critical administration, unpause functions, supply-cap updates, and fee changes. |
| **Oracle Soundness** | Validates that acceptable data-staleness bounds are explicitly declared. |
| **Bridge Security** | Ensures strict volume rate limits are defined across cross-chain parameters. |
| **Treasury Integrity** | Verifies that financial distribution splits sum precisely to target allocations. |
| **Chain Alignment** | Confirms target EVM chain IDs are pinned explicitly to prevent replay vectors. |
| **Intent Signing (CG034)** | Asserts that reviewed and executed calldata hashes match identically; runs strict selector and Safe-module allowlists. |
| **Drift Detection** | Compares live network-state JSON snapshots against the manifest shipped in code. |

The exhaustive ruleset is maintained inside [`policies/catalog.md`](policies/catalog.md).

## Architecture Boundaries

ProtocolGate maintains clear, transparent boundaries regarding its position in the security lifecycle:

- **Manifest dependency.** The engine evaluates the topology you declare in code. If a manifest contains falsified configuration variables, the engine processes those variables as ground truth.
- **Input-driven hashing.** The CG034 rule verifies that the provided input hashes are present, well-formed, and equal. It does not independently compute hashes from active mempools or signature payloads.
- **Complements the stack.** This tool is an independent infrastructure layer. It runs alongside code audits, fuzzing frameworks, and runtime monitoring solutions — it does not replace them.
- **Static execution engine.** The core CLI does not query live RPC nodes, fetch real-time Safe transactions, or simulate transactions out of the box. It evaluates the facts you pass directly to it.
- **Pure determinism.** The ruleset is built on boolean logic. The engine contains no probabilistic machine-learning models, no flaky heuristics, and makes zero network calls during evaluation.

## Extended Documentation

- [Proposal Intent Gate (CG034)](docs/PROPOSAL_INTENT_GATE.md) — detailed engineering deep dive into the calldata-matching system
- [Invariant Hunter](docs/INVARIANT_HUNTER.md) — guide for the CG039 hunt rule
- [Policy Catalog](policies/catalog.md) — index of every rule, severity mapping, and remediation step

*Optional integration:* Pairing this repository with [Vestige](https://github.com/samvallad33/vestige) (AGPL-3.0) introduces shared cross-engagement memory. This is completely decoupled — ProtocolGate functions natively without external dependencies.

## License

Licensed under the Apache-2.0 License. See [LICENSE](LICENSE) for details.
