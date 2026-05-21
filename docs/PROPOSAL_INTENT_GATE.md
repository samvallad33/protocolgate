# Proposal Intent Gate

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
