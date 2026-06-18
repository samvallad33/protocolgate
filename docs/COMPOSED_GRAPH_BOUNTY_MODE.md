# ComposedGraph And Bounty Composition Mode

Status: Phase 1 implemented for local verdict capsules, with the matching
Vestige ComposedGraph storage/tooling implemented in the companion Vestige
worktree.

This document describes the ProtocolGate/Vestige integration layer. Phase 1 is
implemented in the CLI as local JSONL verdict capsules. Vestige now has the
durable ComposedGraph primitives that can store composition events, label
outcomes, and rank never-composed lanes. The current ProtocolGate engine remains
a deterministic manifest, hunt, drift, proposal-intent, and bounty-scope tool.

## Thesis

ProtocolGate became more useful when it stopped treating security review as a
single static scan and started preserving the shape of prior hunt work:

- what was tested;
- what evidence made it real;
- what killed the lane;
- what bounty wording or scope issue mattered;
- what invariant shape should be tried again elsewhere.

ComposedGraph turns that into a product primitive.

```text
memory A + memory B + target context -> composition event -> outcome
```

The important edge is not generic graph memory. The edge is remembering which
facts, bug shapes, and closed doors have and have not been productively composed.

## Why This Matters For Bounty Work

Most scanners preserve positives: alerts, paths, call graphs, counterexamples,
fuzz corpora, and audit issues. Bounty hunting also needs negative and
compositional memory:

- "we tried this lane and impact failed";
- "this depended on trusted-role behavior";
- "this was likely duplicate risk";
- "this needed live config proof";
- "oracle drift and delayed settlement were reviewed separately but never
  composed together";
- "this repo has the same global-invariant/local-gate shape as the Aave lane."

That is the path from memory to new attack ideas.

## Relationship To ProtocolGate

ProtocolGate should feed structured scan outcomes into Vestige. Vestige should
then compose across prior outcomes and hand ProtocolGate the next best lanes.

The flow:

```text
ProtocolGate validate / hunt / drift / bounty-scope
  -> verdict capsule
  -> Vestige ComposedGraph
  -> never-composed attack lanes
  -> targeted agent / PoC / source-review task
  -> outcome label
  -> stronger future routing
```

ProtocolGate remains the deterministic policy and evidence layer. Vestige is the
institutional memory and composition layer. Neither should claim a bounty finding
without source review, scope review, and PoC evidence.

## Verdict Capsules

Every ProtocolGate validate, hunt, drift, or bounty-scope pass can emit a compact
structured capsule.

```yaml
verdict_capsule:
  target: aave-v3.7
  lane: global_invariant_local_gate
  invariant_tested: liquidation grace should protect affected users
  protocol_objects:
    - Pool
    - ValidationLogic
    - ReserveData.liquidationGracePeriodUntil
  source_refs:
    - src/contracts/protocol/libraries/logic/ValidationLogic.sol
  role_assumptions:
    attacker: public liquidator
    trusted_roles_required: false
  live_config_assumptions:
    chain: base
    requires_live_reserve_config: true
  result: submitted_finding
  evidence:
    poc: test/AaveV37BaseGraceBypassImpact.t.sol
    command: forge test -vv --match-path test/AaveV37BaseGraceBypassImpact.t.sol
  blockers: []
  reopen_if: []
```

Capsules should also represent killed lanes:

```yaml
verdict_capsule:
  target: dreusd
  lane: reward_dust_residual
  result: killed_duplicate_risk
  kill_reason: same ERC4626 zero-supply family as submitted high
  evidence_checked:
    - scratch PoC
    - submitted issue #1 impact surface
  reopen_if:
    - distinct user loss path not covered by first-share zero-mint finding
```

## Negative Knowledge Tags

Closed doors should be first-class, not buried in prose.

Recommended tags:

- `closed-door`
- `weak-impact`
- `duplicate-risk`
- `trusted-role-only`
- `needs-live-config`
- `needs-poc`
- `scope-blocked`
- `validated-lane`
- `submitted-finding`
- `accepted-finding`
- `rejected-finding`
- `resurrect-on-change`

The purpose is speed. Future agents should know what not to re-hunt unless a
specific reopen condition is met.

## Never-Composed Lane Generation

Bounty Composition Mode should rank memory pairs or triples that are near each
other but have no prior composition outcome.

Example:

```text
oracle drift + delayed settlement + transferable withdrawal NFT
```

Output:

```yaml
never_composed_lane:
  title: Delayed settlement may pay a stale in-band oracle quote
  source_memories:
    - oracle drift findings
    - withdrawal queue / NFT findings
  boundary_crossed:
    - time
    - oracle
    - settlement
  why_interesting: request-time quote is paid at fill-time after delay
  first_test:
    - locate request/claim storage
    - prove quote snapshots at request
    - warp through fill delay
    - assert no repricing at settlement
  kill_conditions:
    - settlement reprices from oracle
    - amount is explicitly user-owned fixed claim by design and scope accepts it
    - exploit requires malicious oracle data
```

## Composition Score

Never-composed lanes should be ranked with a score that rewards useful
cross-boundary tension.

Suggested signals:

- shared concepts;
- different source domains;
- prior bounty-success similarity;
- direct fund-impact likelihood;
- public exploitability likelihood;
- evidence availability;
- cross-boundary coverage:
  - time;
  - chain;
  - role;
  - oracle;
  - queue;
  - settlement;
  - keeper;
  - upgrade;
  - pause;
  - accounting.

The best ideas usually cross a boundary. Same-file similarity is often less
valuable than "two harmless mechanisms become dangerous together."

## Bounty Composition Mode

When the active workflow is Sherlock, Immunefi, audit-contest, bounty-scope, or
ProtocolGate hunt, the memory layer should return:

- already-composed lanes;
- never-composed lanes;
- stale/dead lanes to avoid;
- duplicate-risk lanes;
- top weird combinations worth testing;
- evidence gaps for each candidate;
- suggested next agent task.

Example output:

```text
Top weird lane:
  global account predicate + route-local validation + user protection window

Why:
  This previously produced the Aave grace-bypass shape.

First task:
  Find functions where a global user state authorizes an action but validation
  checks only selected assets/routes/domains.
```

## Dead-Lane Compiler

The Dead-Lane Compiler converts killed hypotheses into reusable constraints.

Each record should preserve:

- hypothesis;
- files/contracts checked;
- exact blocker;
- scope or severity reason;
- tests run;
- confidence;
- reopen condition;
- related invariant family.

This prevents agents from spending contest time on doors that were already
closed.

## Evidence Gap Orchestrator

Once a lane looks plausible, agents should not keep "auditing everything."
They should close the weakest proof gap:

- source reference;
- fork PoC;
- economic impact;
- scope citation;
- live config;
- exploit preconditions;
- counterexample;
- severity fallback.

The output should be an assignment, not a brainstorm.

```text
Candidate: account-global/local-gate bypass
Weakest gap: no live Base config proof
Agent task: query deployed reserve config and produce exact assets/parameters
```

## Implementation Path

### Phase 1: ProtocolGate Emits Capsules

Status: implemented.

`validate`, `hunt`, `drift`, and `bounty-scope` can append local JSONL capsule
records:

```bash
uv run protocolgate validate protocolgate.yaml --capsules .protocolgate/capsules.jsonl
uv run protocolgate hunt protocolgate.yaml --capsules .protocolgate/capsules.jsonl
uv run protocolgate drift protocolgate.yaml live-state.json --capsules .protocolgate/capsules.jsonl
uv run protocolgate bounty-scope scope.md --candidate candidate.md \
  --capsules .protocolgate/capsules.jsonl
```

No Vestige dependency is required for this phase.

Each capsule is `protocolgate.verdict_capsule.v1` and includes:

- stable capsule ID;
- workflow: `validate`, `hunt`, `drift`, or `bounty-scope`;
- target and target name;
- lane/result/status;
- tags such as `open-door`, `closed-door`, `needs-evidence`, or
  `validated-lane`;
- normalized evidence summary including `invariant_tested`,
  `files_contracts`, `role_assumptions`, `live_config_assumptions`, and
  `poc_status`;
- blockers and missing evidence;
- next actions;
- reopen conditions;
- memory write status, currently `local_only`.

### Phase 2: Vestige Stores Composition Events

Vestige adds durable composition tables:

- `composition_events`
- `composition_members`
- `composition_outcomes`

Deep-reference and bounty-mode workflows write composition events with member
memory IDs, query context, output preview, and later outcome labels.

Status: implemented in the companion Vestige worktree.

### Phase 3: ProtocolGate Writes To Vestige

Status: not implemented.

ProtocolGate should eventually post already-emitted verdict capsules to the
local Vestige API with an explicit opt-in flag:

```bash
uv run protocolgate hunt protocolgate.yaml \
  --capsules .protocolgate/capsules.jsonl \
  --sync-capsules
```

This flag is not implemented yet. When it exists, it must remain advisory. If
Vestige is unavailable, ProtocolGate output must degrade gracefully.

### Phase 4: Never-Composed Queue

Vestige exposes a `composed_graph` or equivalent tool that can return:

- high-value uncomposed pairs/triples;
- co-used neighbors;
- prior outcomes;
- dead-lane blockers;
- bounty-mode ranked lanes.

Status: implemented in the companion Vestige worktree through the
`composed_graph` MCP tool. ProtocolGate still emits local capsules instead of
writing directly to Vestige.

ProtocolGate can then display those lanes as a planning surface before agents
or PoC generation start.

## Guardrails

Do not claim:

- ProtocolGate automatically proves never-composed lanes are bugs.
- Memory can replace source review or PoC validation.
- A killed lane is permanently impossible.
- A composition score is severity.
- A similarity match is duplicate proof.

Say this instead:

> Bounty Composition Mode uses prior hunt memory to route attention toward
> high-value unexplored combinations and away from already-killed lanes. A
> candidate still needs source references, scope fit, and PoC evidence before it
> becomes a submission.

## Why This Is Huge

This is the same mental shape as ProtocolGate itself:

```text
two things exist separately
they are assumed safe separately
the dangerous gap appears when they are checked together
```

ProtocolGate applies that to protocol control planes. ComposedGraph applies it
to the hunt memory that finds those gaps faster.
