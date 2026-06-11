# ProtocolGate

ProtocolGate is a Web3 control-plane policy gate for audit and bounty
readiness: a declarative manifest plus reusable controls for smart-contract
deployment topology, privileged proposal intent, and operational authority.

It treats smart-contract deployment topology like infrastructure. Before a
launch, audit, upgrade, bounty program, or privileged signing flow,
ProtocolGate checks the declared control plane: proxy admins, multisig
thresholds, timelock delays, treasury splits, oracle assumptions, bridge
limits, emergency powers, proposal evidence, and upgrade safety.

The commercial wedge is narrow:

> ProtocolGate helps Web3 teams separate real control-plane exploit paths from
> scary-looking but bounded exposures before audit, bounty triage, or public
> researcher pressure.

## The Sharp Thesis

Smart-contract security is not only code security.

A protocol can pass a source-code audit and still expose users to serious
control-plane risk if the system is operated through weak admin paths. The
dangerous questions often sit just outside the Solidity diff:

- Who can upgrade the proxy?
- Who owns the proxy admin?
- Can one EOA pause, unpause, mint, upgrade, or change fees?
- Is the timelock delay real, or is it bypassed by a guardian, module, or
  undocumented admin?
- Are multisig thresholds strong enough to matter?
- Are Safe or Squads modules allowed to execute transactions outside the normal
  signer threshold?
- Does the proposal text match the calldata signers are approving?
- Was the privileged transaction simulated before signatures were collected?
- Are oracle, bridge, treasury, and supply-control assumptions declared in one
  reviewable place?
- Did any of those assumptions drift after launch?

ProtocolGate exists because those questions are too important to live only in
audit notes, deployment scripts, private spreadsheets, or Slack threads. The
expected control plane should be a versioned artifact. It should be checked in
CI. It should produce findings that engineers, auditors, governance delegates,
and security teams can review before production changes go live.

For buyers, the first product is a fixed-scope Audit and Bounty Readiness
Review: map the protocol's authority layer, run policy checks, trace the
highest-risk scary exposures, and return a report that can be used before
launch, audit, upgrade, or bounty expansion.

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

## Where ProtocolGate Fits

ProtocolGate is intentionally narrow. It is not trying to replace the products
teams already use for source analysis, multisig execution, deployment
management, simulation, monitoring, or audits. It sits between those workflows
as a policy and evidence layer.

| Workflow | Existing Tooling Often Handles | ProtocolGate Adds |
| --- | --- | --- |
| Smart-contract audit | Manual source review, vulnerability findings, bespoke threat model | Repeatable checks for deployment and operational assumptions that audits often list as preconditions |
| Deployment | Scripts, deploy plugins, deploy dashboards, approval processes | A declared expected topology that can fail CI before unsafe production configuration ships |
| Multisig signing | Safe/Squads signer collection and execution | Proposal intent, expiry, calldata hash binding, selector policy, module allowlist, simulation evidence, monitor coverage |
| Governance | Voting, queueing, timelock execution | A machine-checkable view of who can change what, through which delay path, and under what review evidence |
| Monitoring | Alerts, transaction traces, runtime detection | A baseline manifest for detecting control-plane drift from the approved model |
| Security reporting | Audit reports, bounty triage, and risk memos | Audit-style findings for control-plane configuration, plus notes that separate real exploit paths from noisy exposure before launch, upgrade, or bounty |

The best mental model is:

```text
protocolgate.yaml
  -> load + normalize expected control-plane manifest
  -> run built-in policy engine
  -> emit findings as table, JSON, or Markdown
  -> fail CI before deployment if unsafe
  -> later compare expected topology against observed state for drift
```

## The Risk Class

ProtocolGate focuses on the authority layer around contracts:

- upgrade authority
- pause and unpause authority
- proxy admin ownership
- multisig threshold quality
- timelock delay quality
- guardian and emergency powers
- Safe/Squads modules and guards
- governance proposal intent
- oracle configuration and failure behavior
- bridge rate-limit assumptions
- treasury split correctness
- fee and supply-control bounds
- storage-layout and initializer upgrade safety
- chain ID and deployer assumptions
- drift between declared topology and observed state

This is the Web3 control plane: the part of the system that determines who can
change production behavior after deployment.

## Why The Manifest Matters

The manifest is not bureaucracy. It is the boundary between "we think the
protocol is controlled safely" and "we can show the expected control plane in a
file, run policy against it, and review the findings."

ProtocolGate makes the control plane:

- **Declarative:** the expected topology is written down as data.
- **Versioned:** changes to admin paths become code-reviewable diffs.
- **Testable:** the CLI can fail unsafe configurations.
- **Portable:** findings can be emitted as table, JSON, or Markdown.
- **Audit-friendly:** recurring assumptions become named rule findings.
- **CI-friendly:** unsafe topology can block release workflows.
- **Drift-aware:** the same model can later be compared against observed state.

## Source Signals This Integrates With

ProtocolGate is not built in a vacuum. It lines up with security pressure that
already exists across the ecosystem:

- OpenZeppelin Defender documents secure deploy and upgrade workflows,
  production/test environments, approval processes, CI/CD compatibility, and
  deployment history:
  <https://docs.openzeppelin.com/defender/module/deploy>
- Safe documents modules as extensions that can execute transactions from a
  Safe and warns that modules can be a security risk if untrusted:
  <https://docs.safe.global/advanced/smart-account-modules>
- Tenderly exposes simulation, alerting, monitoring, and CI-oriented testing
  primitives:
  <https://docs.tenderly.co/>
- Security Alliance documents governance proposal security practices such as
  proposal review, calldata verification, simulation, and monitoring:
  <https://frameworks.securityalliance.org/devsecops/governance-proposal-security/>
- OWASP Smart Contract Security covers administrative key risk and proxy /
  upgradeability weaknesses:
  <https://scs.owasp.org/SCWE/SCSVS-AUTH/SCWE-155/>
  and
  <https://scs.owasp.org/sctop10/SC10-ProxyAndUpgradeabilityVulnerabilities/>

ProtocolGate's wedge is to turn these kinds of operational security assumptions
into a concrete manifest and policy gate instead of leaving them scattered
across tools, docs, and human memory.

## Quickstart

From a checkout of this repository:

```bash
uv run protocolgate validate examples/protocolgate.valid.yaml
uv run protocolgate validate examples/protocolgate.proposal-intent.yaml
uv run protocolgate export-input examples/protocolgate.valid.yaml
```

The invalid manifest is expected to fail and emit machine-readable findings:

```bash
uv run protocolgate validate examples/protocolgate.invalid.yaml --output json
```

Generate an audit-reviewable control-plane report:

```bash
uv run protocolgate validate examples/protocolgate.invalid.yaml --output markdown
```

See `docs/SAMPLE_CONTROL_PLANE_REPORT.md` for an example report generated from
the intentionally unsafe manifest.

Run bounty-oriented invariant hunting separately from deployment validation:

```bash
uv run protocolgate hunt examples/protocolgate.aave-grace-bypass.yaml
uv run protocolgate hunt examples/protocolgate.aave-grace-bypass.yaml --output markdown
```

Hunt mode looks for control-plane safety mismatches that need deeper PoC work.
The first hunt rule, `CG039`, flags safety controls whose scope is narrower than
the predicate they claim to protect, such as a reserve-scoped liquidation grace
guard protecting an account-global health-factor predicate.

See `docs/INVARIANT_HUNTER.md` for the Aave-style scope-mismatch model.

For the promotion-ready demo talk track, including the 60-second blast script,
5-minute Loom script, exact commands, and outreach copy, see
`docs/KILLER_DEMO_SCRIPT.md`.

## Audit And Bounty Readiness

ProtocolGate is strongest when a team is about to expose its system to external
review:

- pre-audit readiness
- audit-contest preparation
- public bounty launch or expansion
- major governance proposal
- cross-chain deployment
- proxy admin or multisig migration
- oracle, bridge, vault, market, asset, fee, mint, burn, or withdrawal-control
  change

The buyer output is not "we found every bug." The output is:

- `protocolgate.yaml` as the declared authority map
- audit-style findings for unsafe or missing control-plane assumptions
- proposal/signing evidence checks
- bounty-readiness notes for scary-looking exposures
- remediation order for the team

See `docs/CONTROL_PLANE_REVIEW_OFFER.md` for the paid review packages.

## ProtocolGate Revenue OS MCP

ProtocolGate includes a local MCP server for the B2B contract hunt:

```bash
uv run protocolgate-mcp
```

It helps score Web3 leads, draft non-spam outreach, forecast bounty-noise
lanes, prepare founder calls, build mini buyer reports, and log follow-ups.
It does not scrape LinkedIn or auto-send messages.

See `docs/PROTOCOLGATE_REVENUE_OS_MCP.md`.

The drift example is also expected to fail because the live-state snapshot
intentionally disagrees with the manifest:

```bash
uv run protocolgate drift examples/protocolgate.valid.yaml examples/live-state.drift.json --output json
```

Use the experimental OPA/Rego subset when `opa` is installed:

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

## What A Good Manifest Proves

A passing manifest does not prove the protocol is safe. It proves a narrower and
valuable thing: the declared control-plane topology satisfies the current
ProtocolGate policy checks.

That means the manifest can answer questions such as:

- Is the production chain pinned?
- Are expected deployment signers declared?
- Are upgradeable proxies controlled by timelocked governance?
- Are proxy admins separate from fragile EOAs?
- Are admin-only functions routed through a 24h+ delay where required?
- Are pause and upgrade authorities separated?
- Are multisig thresholds stronger than paper multisigs?
- Are treasury splits mathematically complete?
- Are oracle staleness and failure modes bounded?
- Are bridge limits declared?
- Are upgrade safety checks declared?
- Are privileged proposals tied to signer-readable intent and exact calldata?
- Are Safe/Squads modules explicitly allowlisted?

This is the core product: not a vague checklist, but named controls with paths,
severities, findings, and remediation guidance.

## GitHub Actions

For this repository:

```yaml
- uses: astral-sh/setup-uv@v5
- run: uv run pytest
- run: uv run protocolgate validate protocolgate.yaml
```

As a composite action from this repo:

```yaml
- uses: actions/checkout@v4
- uses: your-org/protocolgate/action@main
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

## Optional Advisory Evidence

Deterministic findings tell the team what policy failed. Some teams also need
the audit note, governance decision, or operating policy that explains why that
finding matters. ProtocolGate can attach advisory evidence to findings, but the
rule engine remains the only decision-maker: evidence can explain a finding, not
approve, veto, or change it.

## Buyer-Facing Use Cases

ProtocolGate is useful when a team needs to make control-plane assumptions
visible before money, governance, public researcher attention, or reputation is
on the line.

For a more detailed buyer-facing offer, see
`docs/CONTROL_PLANE_REVIEW_OFFER.md`.

### Pre-Launch Readiness

Before mainnet launch, a protocol can create `protocolgate.yaml` and validate
whether its upgrade path, multisig threshold, timelock, guardian model, oracle
settings, bridge limits, treasury splits, and deployment assumptions meet the
expected policy floor.

### Pre-Audit Evidence

Before a code audit starts, a protocol can give auditors a control-plane
manifest instead of forcing them to reconstruct admin topology from scripts,
docs, and scattered addresses.

### Pre-Bounty Triage

Before opening or expanding a bug bounty, a protocol can identify which
authority paths are missing controls, which scary-looking exposures need
exploit-path validation, and which paths are bounded by existing checks. That
reduces duplicate noise and gives triage evidence before researchers arrive.

### Pre-Upgrade Gate

Before an upgrade is queued or signed, ProtocolGate can check whether the admin
path, storage layout declaration, initializer lock, proposal intent, calldata
hash, simulation status, and monitor coverage are present.

### Governance / Multisig Review

For high-impact proposals, the Proposal Intent Gate adds a signer-review layer:
human-readable metadata, expiry, selector policy, calldata binding,
module/guard allowlists, simulation evidence, and monitor coverage.

### Post-Deploy Drift Review

After launch, the expected topology can be compared against a snapshot. If the
proxy admin, timelock delay, multisig threshold, owner set, guardian role, or
oracle address changed unexpectedly, that drift should be visible.

## What ProtocolGate Is Not

ProtocolGate should be described precisely.

It does not replace:

- smart-contract audits
- formal verification
- fuzzing
- static analysis
- runtime monitoring
- Safe, Squads, Defender, Tenderly, Forta, Hypernative, or other operational
  security platforms

The institutional-memory layer is advisory by design: no LLM or retrieval
system is ever in the decision path. The deterministic rule engine alone
produces findings and exit codes.

It also does not currently:

- query live RPC directly
- fetch Safe transactions directly
- fetch Snapshot or Tally proposals directly
- run Tenderly simulations directly
- query Defender monitors directly
- ingest Slither output directly
- prove Solidity source-code correctness

The current MVP validates declared manifests, emits findings, supports a
snapshot-based drift detector, and demonstrates how Web3 control-plane policy
can be made CI-checkable.

## Positioning

ProtocolGate is not another OPA starter repo and not another smart-contract
scanner. The category is Smart Contract DevSecOps, specifically Web3
control-plane security.

It complements audits by checking deployment and operational assumptions that
should not live only in a checklist: who can upgrade, who can pause, whether
admin power is behind a multisig and timelock, whether treasury and oracle
assumptions are bounded, and whether live state drifted from the manifest.

Short version:

> Audits check the code. ProtocolGate checks the control plane around the code.

Longer version:

> ProtocolGate helps Web3 teams treat deployment topology as a security
> artifact. It declares the expected control plane, runs reusable policy checks,
> emits audit-style findings, fails CI when assumptions are unsafe, and provides
> a baseline for future drift detection.
