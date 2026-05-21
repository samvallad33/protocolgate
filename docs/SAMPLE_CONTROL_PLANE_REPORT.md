# ProtocolGate Control-Plane Report

**Target:** `examples/protocolgate.invalid.yaml`

**Result:** FAIL

## Summary

- Critical: 6
- High: 15
- Medium: 9
- Low: 0

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

## Scope Note

ProtocolGate validates declared deployment topology and control-plane invariants. It does not replace a full smart-contract audit, formal verification, or runtime monitoring.
