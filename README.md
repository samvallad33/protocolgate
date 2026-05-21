# ProtocolGate

ProtocolGate is a Smart Contract DevSecOps tool for Web3 control-plane
security: a declarative manifest plus reusable controls for smart-contract
deployment topology.

It treats smart-contract deployment topology like infrastructure. Before a
deploy run, ProtocolGate checks the declared control plane:
proxy admins, multisig thresholds, timelock delays, treasury splits, oracle
assumptions, bridge limits, emergency powers, and upgrade safety.

## Why This Exists

Static analyzers catch source-level bugs. Audit reports catch bespoke failure
modes. Tools such as Safe, OpenZeppelin Defender, and Tenderly help teams
approve, execute, simulate, and monitor protocol operations.

ProtocolGate focuses on a narrower layer: the control-plane assumptions around
deployment and privileged operations. Those assumptions often still live in
spreadsheets, audit notes, deployment scripts, or informal checklists.

ProtocolGate turns recurring audit findings into reusable policy controls:

- Upgradeable contracts cannot ship with EOA admins.
- Redemption flows must have cooldown, circuit breaker, and pause controls.
- Token, oracle, and accounting decimals must match at integration boundaries.
- Bridge contracts must declare rate limits.
- Observed chain-state snapshots can be compared against the declared manifest
  for drift.
- Privileged proposal intent can be checked before signing: signer-readable
  intent, expiry, calldata hash binding, selector allowlists, Safe module
  allowlists, simulation evidence, and monitor coverage.

## Quickstart

```bash
uv run protocolgate validate examples/protocolgate.valid.yaml
uv run protocolgate validate examples/protocolgate.proposal-intent.yaml
uv run protocolgate export-input examples/protocolgate.valid.yaml
uv run protocolgate drift examples/protocolgate.valid.yaml examples/live-state.drift.json
```

The invalid manifest is expected to fail and emit machine-readable findings:

```bash
uv run protocolgate validate examples/protocolgate.invalid.yaml --output json
```

Generate a buyer-readable control-plane report:

```bash
uv run protocolgate validate examples/protocolgate.invalid.yaml --output markdown
```

See `docs/SAMPLE_CONTROL_PLANE_REPORT.md` for an example report generated from
the intentionally unsafe manifest.

Use the experimental OPA/Rego pack when `opa` is installed:

```bash
uv run protocolgate validate examples/protocolgate.invalid.yaml --engine opa --policy-dir policies
```

## Public Case-Study Fixtures

ProtocolGate now includes public repo fixtures for real protocol control-plane
shapes:

```bash
uv run protocolgate validate examples/public/compound-comet-usdc/protocolgate.yaml
uv run protocolgate validate examples/public/lido-core-mainnet/protocolgate.yaml
uv run protocolgate validate examples/public/aave-governance-v3-ethereum/protocolgate.yaml
```

Each fixture includes `SOURCE_NOTES.md` explaining which public repo files were
used and which fields are modeled ProtocolGate abstractions. These are demo and
study fixtures, not live-state assertions or audits of those protocols.

## Manifest Shape

`protocolgate.yaml` declares the security-relevant deployment topology:

```yaml
version: 1
deployment:
  environment: production
  chain_id: 1
  allowed_deployers: [ProtocolMultisig]
multisigs:
  - name: ProtocolMultisig
    threshold: 3
    signers: ["0x...", "0x...", "0x...", "0x...", "0x..."]
timelocks:
  - name: ProtocolTimelock
    delay_seconds: 172800
    proposer: ProtocolMultisig
    executor: ProtocolMultisig
governors:
  - name: ProtocolGovernor
    voting_delay_seconds: 86400
    voting_period_seconds: 172800
    timelock: ProtocolTimelock
contracts:
  - name: Vault
    type: vault
    upgradeable: true
    proxy:
      admin: ProtocolTimelock
```

See `examples/protocolgate.valid.yaml` for a complete topology.

## GitHub Actions

For this repository:

```yaml
- uses: astral-sh/setup-uv@v5
- run: uv run pytest
- run: uv run protocolgate validate protocolgate.yaml
```

As a composite action from this repo:

```yaml
- uses: <owner>/<repo>/action@main
  with:
    manifest: protocolgate.yaml
```

## Policy Catalog

The current built-in engine implements CG001-CG026 and CG032-CG038. CG027-CG031
are planned future topology and protocol-control rules.

The Rego pack is an experimental subset for teams that already standardize on
OPA; the built-in engine is the canonical implementation during the MVP phase
and the Rego pack should not be described as full parity yet.

See `policies/catalog.md`.

## Drift Detection

The first drift detector accepts a JSON chain-state snapshot:

```bash
uv run protocolgate drift protocolgate.yaml live-state.json
```

A future adapter should collect this snapshot from Etherscan, Alchemy, or direct
RPC:

- proxy admin slots
- timelock delay values
- multisig thresholds and owners
- guardian roles
- oracle feed addresses

## Proposal Intent Gate

The Proposal Intent Gate asks:

> Is this privileged multisig or governance proposal safe to sign and execute?

When a manifest includes `proposal_intent`, the built-in engine validates:

- human-readable signer intent
- proposal creation time and expiry
- reviewed calldata hash versus execution calldata hash
- privileged selector allowlists
- Safe/Squads module allowlists
- transaction simulation evidence
- monitor coverage for high-risk admin changes

Run the focused example:

```bash
uv run protocolgate validate examples/protocolgate.proposal-intent.yaml
```

See `docs/PROPOSAL_INTENT_GATE.md` for the implementation guide and demo
script.

## Positioning

ProtocolGate is not another OPA starter repo and not another smart-contract
scanner. The category is Smart Contract DevSecOps, specifically Web3
control-plane security.

It complements audits by checking deployment and operational assumptions that
should not live only in a checklist: who can upgrade, who can pause, whether
admin power is behind a multisig and timelock, whether treasury and oracle
assumptions are bounded, and whether live state drifted from the manifest.
