# ProtocolGate Control-Plane Report

**Target:** `examples/protocolgate.invalid.yaml`

**Result:** FAIL

**Report type:** Sample audit and bounty readiness review

**Scope:** Declared deployment topology, privileged proposal intent, and
snapshot-style control-plane assumptions. This report does not review Solidity
source code and does not replace a smart-contract audit.

## Executive Summary

ProtocolGate found a fragile control plane around the sample protocol.

The code could be perfectly audited and the system would still be dangerous to
operate because the authority layer is weak:

- an upgradeable vault is controlled by an EOA-style admin path
- privileged admin functions are not routed through a strong timelock
- the multisig is a paper multisig
- treasury splits do not add up to 100%
- redemption controls are incomplete
- bridge limits are missing
- oracle failure behavior is unsafe
- upgrade safety evidence is missing
- the privileged proposal package is not safe to sign
- Safe module policy is not enforced
- simulation and monitor evidence are missing

This is exactly the class of risk ProtocolGate is designed to expose before an
audit, bounty launch, upgrade, or public researcher review. The manifest is not
just documentation; it is a machine-checkable security artifact and a triage
aid. If this were a real production protocol, the release or bounty expansion
should stop until the control plane is repaired or the scary-looking exposures
are proven bounded.

## Bounty Readiness Summary

The sample protocol is not bounty-ready.

High-signal researcher lanes would include:

- single-key or undefined upgrade authority
- privileged functions bypassing timelock
- proposal calldata mismatch
- unallowlisted Safe module execution
- missing bridge limits
- unsafe oracle failure behavior
- uncapped mint or fee changes

Before a public bounty, the team should either remediate these paths or publish
clear scope/evidence that explains why any scary-looking exposure is bounded by
design. ProtocolGate's job is to force that distinction early: real exploit
path, missing control, expected design, or noisy false positive.

## One-Sentence Finding

The sample protocol has the shape of a system that can be upgraded, reconfigured,
or signed into a dangerous state faster than users, signers, auditors, or
monitors can reliably react.

## Why This Matters

Smart-contract security is not only "does the Solidity code contain a bug?"

A protocol also has an operating system around the contracts:

- deployment signers
- proxy admins
- owners
- guardians
- multisigs
- timelocks
- Safe or Squads modules
- governance proposals
- oracle and bridge parameters
- treasury split rules
- upgrade safety procedures
- monitoring coverage

That operating layer is the Web3 control plane. If it is weak, a protocol can
become unsafe even when the application code has already been reviewed.

ProtocolGate turns those assumptions into explicit findings with:

- rule IDs
- severities
- manifest paths
- plain-English findings
- recommendations
- CI-blockable output
- bounty-readiness notes for triage

## Summary

- Critical: 6
- High: 15
- Medium: 9
- Low: 0

## Highest-Risk Attack Paths

### Attack Path 1: Single-Key Upgrade Authority

The vault is upgradeable, but its proxy/admin path is not protected by a
24h+ timelocked governance controller. The manifest also indicates an EOA-style
upgrade admin.

Why this is severe:

- one compromised key can redirect the vault to malicious logic
- users may not have enough time to exit before the upgrade executes
- monitoring may not have a stable expected topology to compare against
- the protocol may appear audited while the upgrade path remains fragile

Relevant findings:

- `CG001`
- `CG002`
- `CG013`
- `CG014`

Required fix:

- move proxy admin authority to a timelock
- ensure the timelock is controlled by a declared multisig or governor
- require storage layout checks before upgrades
- lock implementation initializers

### Attack Path 2: Paper Multisig Governance

The declared multisig threshold is too weak. A 1-of-N or near-1-of-N multisig
looks like decentralization, but operationally it behaves like a single-key
admin.

Why this is severe:

- one signer can act alone
- signer compromise can become protocol compromise
- the system creates social confidence without matching cryptographic safety
- the signing process cannot be treated as robust governance

Relevant finding:

- `CG010`

Required fix:

- use a real threshold such as 3-of-5 or 5-of-9 depending on operational needs
- verify signer independence
- document signer rotation and emergency procedures

### Attack Path 3: Unsafe Privileged Proposal Signing

The sample proposal is missing signer-readable intent, has an overly long
validity window, has mismatched calldata hashes, uses an unapproved selector,
lacks simulation evidence, and lacks monitor coverage.

Why this is severe:

- signers cannot prove what they reviewed
- a stale proposal can remain dangerous
- reviewed intent and execution payload can diverge
- a privileged selector can modify high-impact protocol state
- the action can execute without simulation evidence
- no monitor is attached to watch the resulting control-plane change

Relevant findings:

- `CG032`
- `CG033`
- `CG034`
- `CG035`
- `CG037`
- `CG038`

Required fix:

- require target, category, selector, and intent
- cap proposal validity at the configured limit
- bind reviewed calldata hash to execution calldata hash
- allowlist privileged selectors
- require passed simulation before signatures
- require monitor coverage for high-risk proposal categories

### Attack Path 4: Hidden Module Execution

The sample Safe module is not in the module allowlist.

Why this is severe:

- modules can create execution paths outside the normal signer threshold
- signers may believe the multisig threshold is the only authority boundary
- unreviewed modules can become hidden control-plane actors

Relevant finding:

- `CG036`

Required fix:

- inventory every Safe/Squads module and guard
- define the purpose of each module
- allowlist only reviewed modules
- remove or disable unknown execution modules

### Attack Path 5: Bad Runtime Assumptions Around Redemptions, Oracles, And Bridges

The sample protocol has incomplete redemption controls, unsafe oracle failure
behavior, stale oracle tolerance, and missing bridge rate limits.

Why this is severe:

- redemption paths can become dangerous during market stress
- stale or fail-open oracle behavior can feed unsafe pricing into protocol logic
- bridges without rate limits can expand blast radius
- missing pause/circuit-breaker/cooldown controls reduce incident-response
  options

Relevant findings:

- `CG004`
- `CG006`
- `CG007`
- `CG008`
- `CG012`

Required fix:

- enforce cooldown, circuit breaker, pause, and nonReentrant controls
- set bounded oracle staleness windows
- require fail-closed oracle behavior
- declare and enforce bridge rate limits

## Findings

| Rule | Severity | Path | Finding | Recommendation |
| --- | --- | --- | --- | --- |
| CG001 | critical | `contracts[0].proxy.admin` | FragileVault is upgradeable but proxy/admin control is not a 24h+ timelocked governance controller | Set proxy.admin to a timelock whose proposer/executor is a declared multisig or governor. |
| CG002 | critical | `contracts[0].proxy.admin` | FragileVault uses an EOA as upgrade admin | Move upgrade authority to a timelock controlled by a declared multisig or governor. |
| CG009 | critical | `treasury.splits` | treasury splits sum to 9000 bps, not 10000 bps | Make treasury allocation basis points sum exactly to 10000. |
| CG010 | critical | `multisigs[0].threshold` | multisig TeamMultisig threshold 1/2 is a paper multisig | Set multisig threshold to at least 2, ideally 3/5 or 5/9. |
| CG033 | critical | `proposal_intent.proposals[0].expires_at` | proposal PG-BAD-001 is valid for 259200 seconds | Limit privileged proposal validity to 86400 seconds or less. |
| CG034 | critical | `proposal_intent.proposals[0].execution_calldata_hash` | proposal PG-BAD-001 execution calldata does not match reviewed intent | Require the reviewed calldata hash and execution calldata hash to match before signing. |
| CG003 | high | `contracts[0].functions[1].timelock` | FragileVault.unpause is admin-only without a 24h+ timelock | Route privileged calls through the protocol timelock. |
| CG003 | high | `contracts[0].functions[2].timelock` | FragileVault.setFeeBps is admin-only without a 24h+ timelock | Route privileged calls through the protocol timelock. |
| CG003 | high | `contracts[0].functions[3].timelock` | FragileVault.mintRewards is admin-only without a 24h+ timelock | Route privileged calls through the protocol timelock. |
| CG004 | high | `contracts[0].functions[0].controls` | FragileVault.redeem lacks redemption controls: circuit_breaker, cooldown, pause | Gate redemption with cooldown, circuit breaker, and emergency pause controls. |
| CG005 | high | `contracts[0].integrations[0].decimals` | FragileVault integration USDC has decimals=18, expected=6 | Normalize precision boundaries at every token, oracle, and accounting integration. |
| CG006 | high | `contracts[1].rate_limits.per_block` | bridge FragileBridge does not declare a per-block rate limit | Add a per-block bridge rate limit and enforce it in the bridge contract. |
| CG011 | high | `contracts[0].functions[1].timelock` | FragileVault.unpause can execute without a 24h+ timelock | Allow emergency pause immediately, but require timelock governance for unpause. |
| CG012 | high | `contracts[0].functions[0]` | FragileVault.redeem has external calls without CEI + nonReentrant controls | Update state before external calls and add nonReentrant protection. |
| CG013 | high | `contracts[0].upgrade_safety.storage_layout_check` | FragileVault does not prove storage layout upgrade checks are enabled | Enable storage layout diff checks in CI before upgrade execution. |
| CG014 | high | `contracts[0].upgrade_safety.initializer_locked` | FragileVault does not declare locked initializers | Lock implementation initializers and verify initialization state in deployment scripts. |
| CG016 | high | `contracts[0].functions[3].timelock` | FragileVault.mintRewards supply control is not timelocked | Put privileged supply changes behind the protocol timelock. |
| CG032 | high | `proposal_intent.proposals[0].intent` | proposal PG-BAD-001 is missing intent | Require privileged proposals to include signer-readable metadata before approval. |
| CG035 | high | `proposal_intent.proposals[0].selector` | proposal PG-BAD-001 uses unapproved privileged selector upgradeToAndCall(address,bytes) | Allowlist selectors that can change upgrades, admins, bridges, oracles, supply, treasury, or emergency controls. |
| CG036 | high | `proposal_intent.safe_modules[0].name` | Safe module RawExecutionModule is not in the module allowlist | Declare and review every Safe or Squads module that can execute transactions outside normal signer flow. |
| CG037 | high | `proposal_intent.proposals[0].simulation.status` | proposal PG-BAD-001 has no passed transaction simulation | Simulate privileged transactions before collecting signatures. |
| CG007 | medium | `oracles[0].max_staleness_seconds` | oracle ETHUSD has unsafe staleness window | Set max_staleness_seconds to 3600 or lower for production feeds. |
| CG008 | medium | `oracles[0].failure_mode` | oracle ETHUSD does not fail closed | Set failure_mode: fail_closed and halt dependent operations when the feed is invalid. |
| CG015 | medium | `contracts[0].functions[3].supply_cap` | FragileVault.mintRewards has no supply cap | Declare and enforce a hard cap or bounded mint/burn envelope. |
| CG017 | medium | `deployment.chain_id` | production deployment does not pin chain_id | Pin chain_id in deployment scripts to prevent wrong-chain execution. |
| CG018 | medium | `deployment.allowed_deployers` | production deployment does not declare allowed deployers | Declare the expected deployer addresses or deployment signer controls. |
| CG019 | medium | `contracts[0].roles.pauser` | FragileVault uses the same authority for pause and upgrade | Separate emergency pause authority from upgrade authority. |
| CG020 | medium | `contracts[0].functions[2].max_bps` | FragileVault.setFeeBps can change fees without max_bps | Declare a hard upper bound for fee-setting logic. |
| CG021 | medium | `contracts[0].functions[2].timelock` | FragileVault.setFeeBps fee change is not timelocked | Route fee changes through the protocol timelock. |
| CG038 | medium | `proposal_intent.proposals[0].monitor.enabled` | proposal PG-BAD-001 has no monitor coverage | Attach monitor coverage to admin, oracle, bridge, treasury, and supply-control proposals. |

## Prioritized Remediation Plan

### Stop-Ship Fixes

These should block launch or upgrade:

1. Move proxy admin and admin roles behind timelocked governance.
2. Replace the paper multisig with a real threshold.
3. Fix proposal calldata hash mismatch.
4. Add signer-readable proposal intent.
5. Declare and allowlist Safe/Squads modules.
6. Add simulation evidence before signatures.
7. Fix treasury basis points to exactly 10000.

### High-Priority Hardening

These should be resolved before production readiness:

1. Route admin-only functions through timelocks.
2. Require timelocked unpause.
3. Add redemption controls.
4. Enable storage layout checks.
5. Lock initializers.
6. Add bridge rate limits.
7. Add fee and supply bounds.
8. Separate pause authority from upgrade authority.

### Operational Controls

These should become ongoing process requirements:

1. Pin chain ID in deployment workflows.
2. Declare allowed deployers.
3. Maintain an owner/module/signature inventory.
4. Re-run ProtocolGate before each high-privilege proposal.
5. Compare observed chain-state snapshots against the manifest for drift.
6. Attach monitor coverage to admin, oracle, bridge, treasury, and supply
   changes.

## What A Passing Follow-Up Should Look Like

A remediated manifest should show:

- `proxy.admin` is a named timelock
- the timelock has a declared proposer and executor
- the proposer/executor resolve to a multisig or governor
- multisig threshold is not 1-of-N
- upgrade safety fields are enabled
- admin functions reference timelocks where required
- pause and upgrade powers are separated
- redemptions have cooldown, circuit breaker, pause, and nonReentrant controls
- bridge rate limits exist
- oracle staleness is bounded
- oracle failures fail closed
- treasury splits sum to 10000 bps
- privileged proposal calldata hashes match
- privileged proposals expire quickly
- Safe/Squads modules are allowlisted
- passed simulation evidence exists
- monitor coverage exists for high-risk categories

## How To Read It

This report is valuable because it gives a protocol team a concrete list of
control-plane weaknesses before the system is live or before signers approve a
dangerous action.

It is not a vague security memo. It is a release gate:

```text
Unsafe topology declared
-> ProtocolGate emits findings
-> CI exits non-zero
-> deployment or signing workflow stops
-> team fixes authority paths
-> report becomes review evidence
```

That is the product wedge: turn Web3 control-plane assumptions into policy,
findings, and release decisions.

## Scope Note

ProtocolGate validates declared deployment topology and control-plane
invariants. It does not replace a full smart-contract audit, formal
verification, runtime monitoring, incident-response readiness, or manual
exploit-path validation. The right positioning is:

> ProtocolGate complements audits by checking deployment and operational
> control-plane assumptions that should not live only in a checklist. Its
> bounty-readiness role is to package evidence, reduce noisy triage, and
> highlight the authority paths that deserve deeper proof.
