# Proposal Intent Gate

The Proposal Intent Gate is the part of ProtocolGate that moves the project
from "deployment topology is safe" into "the privileged action moving through
that topology is safe to review and sign."

This is one of the sharpest wedges in the project.

Every mature Web3 team eventually faces the same uncomfortable reality:
multisigs and governance are not just ceremony. They are production control
planes. A signer can approve a transaction that upgrades a proxy, changes an
oracle, raises a bridge limit, modifies withdrawal controls, mints supply, or
hands admin authority to a different actor. If that transaction is hard to read,
never expires, routes through an unreviewed module, or contains calldata that
does not match the human summary, the security model depends on trust and
attention instead of enforceable evidence.

ProtocolGate's answer is direct:

> A privileged proposal should not be signed unless the intent, calldata,
> authority path, simulation evidence, module boundary, and monitoring coverage
> are declared and checkable.

## Status

The Proposal Intent Gate is active in the built-in ProtocolGate policy engine.
It is implemented in:

- `src/protocolgate/rules_proposal_intent.py`
- `src/protocolgate/rules.py`
- `schema/protocolgate.schema.json`
- `examples/protocolgate.proposal-intent.yaml`
- `tests/test_rules.py`

The OPA/Rego policy pack includes an experimental subset in
`policies/protocolgate/proposal_intent.rego`. The built-in Python engine remains
the canonical implementation.

## The Problem

Smart-contract audits usually focus on source code. That is necessary, but a
protocol can still be operated unsafely if privileged actions are signed without
clear intent, expiry, simulation, module review, or calldata binding.

The Proposal Intent Gate checks a narrower control-plane question:

> Is this privileged multisig or governance proposal safe to sign and execute?

This is different from checking Solidity code. The proposal may call audited
code, but the transaction can still be dangerous if it upgrades the wrong
contract, changes an oracle, changes a bridge limit, mints supply, transfers
admin authority, or uses calldata that does not match what signers reviewed.

## The Failure Mode In Plain English

The classic failure mode looks like this:

1. A team believes a proposal is routine.
2. Signers see a short description, a UI label, or a message from a trusted
   teammate.
3. The raw calldata is not independently bound to the text they reviewed.
4. The proposal does not expire quickly, so stale approval risk remains.
5. A Safe/Squads module or guard path can execute outside the expected human
   signer threshold.
6. No simulation artifact is attached to show what state changes actually
   happen.
7. No monitor is configured for the high-risk state change.
8. The transaction executes and the protocol's control plane changes in a way
   that was not fully reviewed.

ProtocolGate does not try to replace the signing wallet, governance UI,
simulation platform, monitoring stack, or audit firm. It creates the missing
policy layer that says: "These fields must exist before this proposal should be
treated as reviewable."

## The Buyer Value

For a protocol team, Proposal Intent Gate creates a pre-signing checklist that
can be automated:

- signers see the target, category, selector, and intent
- approvals expire instead of living forever
- reviewed calldata and execution calldata must match
- privileged selectors must be known and allowlisted
- Safe/Squads modules must be declared and reviewed
- high-privilege actions must have simulation evidence
- admin/oracle/bridge/supply/withdrawal changes must have monitor coverage

For an auditor, it creates a repeatable way to ask:

- "What exactly are signers approving?"
- "How do we know this calldata matches the proposal intent?"
- "Which module can bypass the normal signer flow?"
- "Is there a simulation artifact?"
- "Who monitors the resulting admin-state change?"

For a governance delegate, it creates a clearer security boundary:

- proposal text is not enough
- UI labels are not enough
- a Safe transaction queue is not enough
- calldata, expiry, module authority, simulation, and monitoring all matter

## What It Checks

The feature validates the `proposal_intent` section of a ProtocolGate manifest.
It only runs when that section is present.

High-privilege proposal categories include:

- `upgrade`
- `admin_transfer`
- `oracle_change`
- `bridge_limit_change`
- `treasury_transfer`
- `mint_cap_change`
- `withdrawal_limit_change`

Default high-privilege selectors include:

- `upgradeTo(address)`
- `upgradeToAndCall(address,bytes)`
- `changeAdmin(address)`
- `grantRole(bytes32,address)`
- `revokeRole(bytes32,address)`
- `setOracle(address)`
- `setBridgeLimit(uint256)`
- `setWithdrawalLimit(uint256)`
- `setFeeBps(uint256)`
- `mint(address,uint256)`
- `pause()`
- `unpause()`

## Rules

| Rule | Severity | Meaning |
| --- | --- | --- |
| `CG032` | High | Privileged proposals need signer-readable metadata: target, category, selector, and intent. |
| `CG033` | Critical | Privileged proposals need `created_at`, `expires_at`, and a bounded validity window. |
| `CG034` | Critical | `reviewed_calldata_hash` must match `execution_calldata_hash`. |
| `CG035` | High | Privileged selectors must be allowlisted by policy. |
| `CG036` | High | Safe/Squads modules must be declared and allowlisted. |
| `CG037` | High | Privileged proposals need a passed transaction simulation. |
| `CG038` | Medium | High-risk admin proposals need monitor coverage. |

## Rule-by-Rule Security Story

### CG032: Signer-Readable Metadata

If a privileged proposal does not clearly state the target, category, selector,
and intent, then signers are being asked to approve an opaque action. That is not
a security process; it is a trust process.

ProtocolGate forces the proposal to become readable before approval:

- what contract is targeted
- what category of action is being executed
- what function selector is being called
- what the human-readable intent claims to be

### CG033: Bounded Validity

Privileged approvals should not live indefinitely. A proposal that made sense
last week may be dangerous after a code change, governance change, market event,
or signer rotation.

ProtocolGate requires creation and expiry timestamps and checks the validity
window against policy.

### CG034: Calldata Hash Binding

This is the most direct signer-safety control.

If the reviewed calldata hash and execution calldata hash differ, the signer
review process is broken. The proposal that people reviewed is not the payload
that will execute.

ProtocolGate treats that as critical because it breaks the link between human
intent and machine execution.

### CG035: Selector Allowlist

Privileged selectors are not normal calls. Functions like `upgradeTo`,
`changeAdmin`, `setOracle`, `setBridgeLimit`, `mint`, `pause`, and `unpause`
can change the safety envelope of the protocol.

ProtocolGate requires high-risk selectors to be declared instead of discovered
after the fact.

### CG036: Safe/Squads Module Allowlist

Modules and guards are part of the security boundary. If a module can execute
transactions outside the normal signer flow, then it deserves the same level of
review as signer thresholds and owners.

ProtocolGate requires modules to be declared and allowlisted so hidden execution
paths are not treated as harmless configuration.

### CG037: Transaction Simulation

High-privilege proposals should be simulated before signatures are collected.
Simulation is not a proof of safety, but it is useful evidence: state changes,
logs, token movements, admin changes, and revert paths become visible before the
proposal reaches production.

ProtocolGate requires the proposal to declare passed simulation evidence when
policy says simulation is mandatory.

### CG038: Monitor Coverage

Some actions deserve immediate monitoring because they change the control plane:

- admin transfers
- oracle changes
- bridge-limit changes
- mint-cap changes
- withdrawal-limit changes

ProtocolGate requires monitor coverage for those categories so a high-risk
change does not execute silently.

## Manifest Shape

```yaml
proposal_intent:
  require_metadata: true
  max_validity_seconds: 86400
  require_calldata_hash_match: true
  require_simulation: true

  privileged_selectors:
    - "upgradeTo(address)"
    - "upgradeToAndCall(address,bytes)"
    - "changeAdmin(address)"
    - "setOracle(address)"
    - "setBridgeLimit(uint256)"
    - "mint(address,uint256)"
    - "setWithdrawalLimit(uint256)"

  allowed_safe_modules:
    - DelayModule
    - RolesModule

  safe_modules:
    - name: DelayModule
      address: "0x6000000000000000000000000000000000000006"
      purpose: "Require delayed execution for privileged Safe transactions."

  monitor_required_for:
    - upgrade
    - oracle_change
    - bridge_limit_change
    - mint_cap_change
    - withdrawal_limit_change

  proposals:
    - id: "PG-001"
      target: MonetrixVault
      category: upgrade
      selector: "upgradeTo(address)"
      intent: "Upgrade MonetrixVault to audited implementation v1.2.0."
      created_at: "2026-05-03T00:00:00Z"
      expires_at: "2026-05-04T00:00:00Z"
      reviewed_calldata_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      execution_calldata_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      simulation:
        provider: tenderly
        status: passed
      monitor:
        enabled: true
        provider: defender
```

## End-To-End Flow

1. A protocol declares privileged proposal policy in `proposal_intent`.
2. A proposal is added with target, category, selector, intent, timestamps,
   calldata hashes, simulation status, and monitor coverage.
3. `uv run protocolgate validate protocolgate.yaml` loads and normalizes the
   manifest.
4. `evaluate_manifest` runs all rule evaluators, including CG032-CG038.
5. Findings are sorted by severity and rule ID.
6. CI fails with exit code `1` if any finding exists.
7. Engineers fix the proposal metadata before signatures are collected.

## Where This Fits In A Real Workflow

The current MVP validates declared proposal metadata. A team can use it like
this:

1. A privileged action is prepared in a governance or multisig workflow.
2. The team records the proposal in `protocolgate.yaml` or generates the
   equivalent manifest entry from an internal process.
3. The entry includes the target, selector, category, human intent, timestamps,
   reviewed calldata hash, execution calldata hash, simulation status, module
   list, and monitor coverage.
4. CI runs ProtocolGate before the proposal is approved or before deployment
   artifacts are merged.
5. Any missing or mismatched evidence becomes a named finding.
6. The team fixes the proposal package before asking signers to approve.

Future adapters can fetch this evidence directly from Safe, Squads, Snapshot,
Tally, Defender, Tenderly, RPC, or internal governance tooling. That is roadmap
work. The current product proves the policy model first.

## What A Strong Proposal Package Looks Like

A high-quality privileged proposal package should include:

- a short title
- target contract name and address
- category of action
- function selector
- exact calldata hash
- signer-readable intent
- reason the action is needed
- creation time
- expiry time
- simulation link or evidence reference
- module/guard review
- monitor coverage
- rollback or incident-response note when relevant

ProtocolGate does not need all of those fields today, but the direction is
clear: privileged actions should become evidence packages, not blind approval
requests.

## Demo Commands

Passing focused Proposal Intent Gate example:

```bash
uv run protocolgate validate examples/protocolgate.proposal-intent.yaml
```

Passing full control-plane manifest:

```bash
uv run protocolgate validate examples/protocolgate.valid.yaml
```

Failing manifest with topology and proposal-intent violations:

```bash
uv run protocolgate validate examples/protocolgate.invalid.yaml
uv run protocolgate validate examples/protocolgate.invalid.yaml --output json
uv run protocolgate validate examples/protocolgate.invalid.yaml --output markdown
```

Run the tests:

```bash
uv run pytest
```

## How To Explain It

Use this explanation:

> ProtocolGate checks the Web3 control plane around smart contracts. The
> Proposal Intent Gate extends that idea from deployment topology into
> privileged proposal safety. Before a multisig or governance action is signed,
> the proposal must be human-readable, bounded by time, tied to the exact
> calldata that will execute, restricted to approved selectors and modules,
> simulated, and covered by monitors when the action changes high-risk admin
> state.

Shorter version:

> Audits check the code. The Proposal Intent Gate checks whether the privileged
> transaction moving through governance is safe to sign.

Aggressive version:

> A multisig signature is not a security control if signers cannot prove what
> they reviewed. Proposal Intent Gate turns privileged approval into a policy
> artifact: intent, expiry, calldata binding, selector policy, module review,
> simulation, and monitoring.

Founder version:

> Before your team signs an upgrade, oracle change, bridge limit change, or
> admin transfer, ProtocolGate checks whether the proposal package is reviewable
> and bounded. It does not replace your audit or your multisig. It makes the
> signing process harder to fake, harder to misunderstand, and easier to review.

Auditor version:

> This turns recurring proposal-review assumptions into deterministic findings.
> Instead of writing "ensure calldata matches intended action" as a manual note,
> ProtocolGate gives that assumption a rule ID, severity, path, and remediation.

## What This Is Not

Do not overclaim this feature.

It does not currently:

- fetch Safe transactions directly
- fetch Snapshot or Tally proposals directly
- run Tenderly simulations directly
- query Defender monitors directly
- decode arbitrary calldata automatically
- replace smart-contract audits
- prove Solidity correctness
- prevent every exploit

Current scope is deterministic validation of declared proposal intent metadata.
That is enough to demonstrate the control-plane security layer without turning
ProtocolGate into a full governance platform.
