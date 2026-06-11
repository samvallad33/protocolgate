# ProtocolGate Killer Demo Script

Use this for Loom, LinkedIn video, X clips, founder DMs, and live calls.

The demo should make one idea stick:

> Audits check code. ProtocolGate checks who can change the code.

Do not sell this as another scanner. Sell the missing security artifact: a
versioned, checkable control-plane map for smart-contract systems.

## Current Demo Proof

These commands were verified on June 11, 2026.

```bash
uv run protocolgate validate examples/protocolgate.valid.yaml
uv run protocolgate validate examples/protocolgate.proposal-intent.yaml
uv run protocolgate validate examples/public/compound-comet-usdc/protocolgate.yaml
uv run protocolgate validate examples/public/lido-core-mainnet/protocolgate.yaml
uv run protocolgate validate examples/public/aave-governance-v3-ethereum/protocolgate.yaml
uv run protocolgate validate examples/protocolgate.invalid.yaml --output markdown
uv run protocolgate drift examples/protocolgate.valid.yaml examples/live-state.drift.json --output json
cd examples/public/dre-labs-dreusd && ./run_demo.sh --no-memory
```

Current strengths:

- Clean reference manifests pass.
- Public protocol topology fixtures pass for Compound III Comet USDC, Lido Core
  Mainnet, and Aave Governance V3 Ethereum.
- The intentionally unsafe manifest fails with 30 audit-style findings:
  6 critical, 15 high, 9 medium.
- Drift detection catches a proxy admin drifting from `ProtocolTimelock` to
  `CompromisedAdmin` and a multisig threshold drifting from 3 to 2.
- The DRE-style proposal demo catches an execution calldata hash that does not
  match reviewed intent, missing simulation evidence, and missing monitor
  coverage.

Current guardrails:

- ProtocolGate complements audits. It does not replace audits.
- The built-in Python engine is canonical today.
- The Rego pack is experimental and should not be described as full parity.
- Drift is snapshot-based today. Do not claim live RPC, Safe, Snapshot, Tally,
  Defender, Tenderly, Etherscan, Alchemy, or Slither ingestion unless separately
  implemented and verified.
- Public fixtures are demo and study fixtures, not audits or live-state
  assertions about those protocols.

## 60-Second Blast Script

Hook:

> Your audit checked the code. Who checked who can change the code?

Talk track:

Smart-contract audits are necessary, but they do not automatically prove the
protocol is safe to operate.

The dangerous layer is often around the contracts:

- who controls the proxy admin
- which multisig can upgrade
- whether unpause is timelocked
- whether bridge limits exist
- whether oracles fail closed
- whether treasury splits add up
- whether a privileged proposal's calldata matches what signers reviewed

That is the Web3 control plane.

ProtocolGate turns that control plane into a manifest and runs policy checks
against it.

Here is the whole idea:

```bash
uv run protocolgate validate examples/protocolgate.invalid.yaml --output markdown
```

This intentionally unsafe protocol fails with 30 findings:

- EOA upgrade admin
- paper multisig
- privileged functions without timelock
- unsafe oracle behavior
- missing bridge limits
- calldata mismatch in a privileged proposal
- missing simulation and monitor coverage

Then this drift check catches the worst post-launch failure mode:

```bash
uv run protocolgate drift examples/protocolgate.valid.yaml examples/live-state.drift.json --output json
```

The manifest expected `ProtocolTimelock`.

The observed state says `CompromisedAdmin`.

That should not be a Slack message. That should be a failing security check.

Close:

> Audits check code. ProtocolGate checks who can change the code.
>
> I am looking for Web3 teams preparing for an audit, bounty, upgrade,
> cross-chain deployment, RWA launch, or stablecoin launch. A 48-hour
> control-plane triage gives you an authority map, top findings,
> bounty-readiness notes, remediation order, and a walkthrough.

## 5-Minute Loom Script

### 0:00 - 0:20: Open With The Problem

Say:

> Smart-contract security is not only code security.
>
> A protocol can have audited Solidity and still be dangerous if the control
> plane is weak.
>
> ProtocolGate is a Web3 control-plane policy gate. Audits check code.
> ProtocolGate checks who can change the code.

Show:

```bash
pwd
ls
```

Then open:

```bash
README.md
```

Point to the thesis:

> deployment topology, privileged proposal intent, and operational authority.

### 0:20 - 1:00: Show The Manifest

Open:

```bash
examples/protocolgate.valid.yaml
```

Say:

> This is the missing artifact. Instead of control-plane assumptions living in
> deploy scripts, audit PDFs, Safe transactions, Notion docs, and team memory,
> they live in a versioned manifest.

Point out:

- production chain and allowed deployers
- multisig threshold
- 48-hour timelock
- proxy admin
- pause guardian
- oracle staleness and fail-closed behavior
- treasury splits
- bridge rate limits
- privileged proposal policy

Then run:

```bash
uv run protocolgate validate examples/protocolgate.valid.yaml
```

Say:

> This does not prove the protocol has no bugs. It proves the declared authority
> topology satisfies the current control-plane checks.

Expected output:

```text
PASS no policy violations
```

### 1:00 - 2:00: Show The Unsafe Topology Becoming Findings

Run:

```bash
uv run protocolgate validate examples/protocolgate.invalid.yaml --output markdown
```

Say:

> Now here is the same idea in reverse. This is an intentionally unsafe control
> plane. ProtocolGate does not just say "bad." It emits audit-style findings:
> rule IDs, severities, manifest paths, findings, and recommendations.

Call out the highest-signal findings:

- `CG001`: upgradeable vault is not behind a 24h+ timelocked governance path
- `CG002`: proxy admin is an EOA
- `CG010`: 1-of-2 paper multisig
- `CG003`: admin-only functions without timelock
- `CG006`: bridge without per-block rate limit
- `CG008`: oracle does not fail closed
- `CG034`: execution calldata does not match reviewed proposal intent
- `CG037`: no passed simulation before signing
- `CG038`: no monitor coverage

Say:

> This is the difference between "we think governance is safe" and "the release
> fails because the authority layer is not reviewable."

### 2:00 - 3:00: Show The Killer Proposal Intent Moment

Run:

```bash
cd examples/public/dre-labs-dreusd
./run_demo.sh --no-memory
```

Say:

> This is the signing-flow demo. The proposal looks routine: raise a daily mint
> cap. But ProtocolGate checks the evidence a signer should demand before
> approving a privileged action.

Point to the three findings:

- `CG034`: execution calldata does not match reviewed intent
- `CG037`: no passed transaction simulation
- `CG038`: no monitor coverage for the mint-cap change

Say:

> This is the part people should remember. A multisig is not magic. Governance
> is not magic. If signers approve calldata that does not match what they
> reviewed, the control plane has failed.

Then say:

> ProtocolGate does not replace Safe, Defender, Tenderly, or auditors. It says
> what evidence must exist before this privileged action should be treated as
> reviewable.

### 3:00 - 4:00: Show Drift

Return to the repo root:

```bash
cd <protocolgate repo path>
uv run protocolgate drift examples/protocolgate.valid.yaml examples/live-state.drift.json --output json
```

Say:

> The manifest is not only pre-launch documentation. It becomes the baseline for
> drift. Here, the reviewed topology expected the vault admin to be
> `ProtocolTimelock`.
>
> The observed snapshot says `CompromisedAdmin`.

Point to:

```json
"message": "proxy admin drifted from manifest",
"expected": "ProtocolTimelock",
"actual": "CompromisedAdmin"
```

Say:

> That should not be discovered by accident. It should be a failing check.

Also point to the multisig threshold drift:

```json
"expected": 3,
"actual": 2
```

Say:

> The reviewed governance model changed. ProtocolGate makes that visible.

### 4:00 - 4:35: Show Public Fixture Credibility

Run:

```bash
uv run protocolgate validate examples/public/compound-comet-usdc/protocolgate.yaml
uv run protocolgate validate examples/public/lido-core-mainnet/protocolgate.yaml
uv run protocolgate validate examples/public/aave-governance-v3-ethereum/protocolgate.yaml
```

Say:

> These are public topology fixtures for recognizable protocol shapes. They are
> not audits and not live-state assertions. They show that this model can
> express realistic Web3 control-plane patterns.

Expected output:

```text
PASS no policy violations
```

### 4:35 - 5:00: Close With The Buyer Ask

Say:

> ProtocolGate is narrow on purpose.
>
> It checks the layer around smart contracts: proxy admins, multisigs,
> timelocks, guardians, bridges, oracles, treasuries, upgrades, proposal intent,
> and drift.
>
> It complements audits by turning deployment and operational assumptions into
> a security artifact.

Close:

> I am looking for Web3 teams preparing for an audit, bounty, upgrade,
> cross-chain deployment, RWA launch, or stablecoin launch.
>
> The first offer is a fixed-scope 48-hour control-plane triage: authority map,
> top findings, bounty-readiness notes, remediation order, and a walkthrough.
>
> Audits check code. ProtocolGate checks who can change the code.

## LinkedIn Post To Pair With The Demo

```text
Your audit checked the code.

Who checked who can change the code?

Every serious protocol has a control plane around the contracts:

- proxy admins
- multisig owners
- Safe modules and guards
- timelocks and governors
- guardians and pause powers
- bridge limits
- oracle admin assumptions
- treasury split rules
- privileged proposal calldata

That layer is usually scattered across deployment scripts, docs, Safe
transactions, audit notes, dashboards, and team memory.

ProtocolGate is my attempt to make it a first-class security artifact.

A manifest says what the authority topology should be.
A policy gate checks it before production.
A findings report turns unsafe assumptions and drift into something founders,
auditors, and bounty teams can act on.

In the demo:

- a clean manifest passes
- an unsafe manifest fails with 30 control-plane findings
- a signing-flow check rejects calldata that does not match reviewed intent
- a drift check catches a proxy admin changing from ProtocolTimelock to
  CompromisedAdmin

It does not replace audits.

It gives audits the authority map they should not have to reconstruct from
scratch.

Audits check code.
ProtocolGate checks who can change the code.

I am looking for 3 teams preparing for an audit, bounty, upgrade, cross-chain
launch, RWA launch, or stablecoin deployment.

Would a 48-hour ProtocolGate control-plane triage be useful before you ship?
```

## Founder DM After They Watch

```text
Appreciate you taking a look.

The simplest way to think about ProtocolGate:

audits check code; ProtocolGate checks who can change the code.

For a 48-hour pass, I would map the authority layer around one protocol, vault,
market, bridge path, or upgrade: proxy admins, multisigs, timelocks, guardians,
oracles, bridge limits, treasury/supply controls, and privileged proposal flow.

Output would be an authority map, top control-plane findings, bounty-readiness
notes, remediation order, and a short walkthrough.

Would that be useful before your next audit, bounty, upgrade, or launch?
```

## Comment Snippets

Use these under posts about audits, bounties, upgrades, multisigs, RWA,
stablecoins, bridges, and governance.

```text
The question I keep coming back to: the code may be audited, but is the
authority layer reviewable? Proxy admins, timelocks, Safe modules, oracle
admins, bridge limits, and proposal calldata should be a security artifact, not
tribal knowledge.
```

```text
For bounties, one hidden cost is control-plane ambiguity. Researchers see a
scary admin/bridge/oracle path; the team has to prove whether it is exploitable,
bounded by design, or just undocumented. That should be mapped before launch.
```

```text
Multisigs are not magic. The signing workflow matters: signer-readable intent,
expiry, calldata hash binding, selector policy, simulation, module review, and
monitor coverage.
```

## Never Say

- "ProtocolGate replaces audits."
- "ProtocolGate proves Solidity correctness."
- "ProtocolGate prevents every exploit."
- "This public fixture proves the protocol is safe."
- "The DRE demo finding is a confirmed live vulnerability."
- "The Rego pack has full parity with the built-in engine."
- "ProtocolGate already pulls live chain state directly from RPC."

## Say Instead

- "ProtocolGate complements audits."
- "ProtocolGate checks the control plane around smart contracts."
- "ProtocolGate turns deployment and operational assumptions into reportable
  findings."
- "ProtocolGate helps teams separate real exploit paths from scary-looking but
  bounded exposures before audit, bounty, upgrade, or launch."
- "The current drift demo compares a declared manifest against a local
  live-state snapshot."
- "The public fixtures are study and demo fixtures, not audits."
