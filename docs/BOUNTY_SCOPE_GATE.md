# ProtocolGate Bounty Scope Gate

The Bounty Scope Gate turns bounty or audit-contest scope text into a
reportability decision:

```text
scope page + candidate notes -> submit / defer / kill
```

This is the anti-noise layer ProtocolGate was missing.

## Why It Exists

Finding a scary control-plane exposure is not enough. A bounty report only
matters if it survives the program's scope, exclusions, evidence rules, and
impact table.

The gate is designed to answer:

- Is this asset or repo in scope?
- Is the impact in scope?
- Is this just trusted-role abuse, centralization risk, best-practice feedback,
  or a known issue?
- Does the program require a PoC?
- Does the candidate have a public actor path?
- Is there real value movement, minting, withdrawal, replay, insolvency, or user
  loss?
- Should we submit, defer for more proof, or kill the report?

## CLI

Parse scope only:

```bash
uv run protocolgate bounty-scope examples/bounty-scope.sample.md
```

Gate a candidate:

```bash
uv run protocolgate bounty-scope \
  examples/bounty-scope.sample.md \
  --candidate examples/bounty-candidate.sample.md
```

Machine-readable output:

```bash
uv run protocolgate bounty-scope \
  examples/bounty-scope.sample.md \
  --candidate examples/bounty-candidate.sample.md \
  --output json
```

Append a local verdict capsule for future composition/memory workflows:

```bash
uv run protocolgate bounty-scope \
  examples/bounty-scope.sample.md \
  --candidate examples/bounty-candidate.sample.md \
  --capsules .protocolgate/capsules.jsonl
```

Capsules are advisory JSONL records. They do not change the `submit`, `defer`,
or `kill` verdict.

## Verdicts

### Submit

Use this only when the candidate has:

- matched in-scope asset, repo, impact, or control-plane surface;
- public or untrusted actor path;
- concrete impact;
- PoC or reproduction evidence when required;
- no trusted-role, centralization, out-of-scope, or known-issue blocker.

### Defer

Use this when the idea may be real, but needs more proof.

Typical defer cases:

- missing PoC;
- impact not stated clearly;
- public actor path is vague;
- "missing rate limit" without value movement, replay, mint, withdraw, or
  accounting break;
- no clear match to an in-scope asset.

### Kill

Use this when the candidate is unlikely to be reportable.

Typical kill cases:

- trusted-role-only or admin-only path when excluded;
- centralization-risk report when excluded;
- best-practice hardening without exploitability;
- known or accepted issue;
- out-of-scope asset, repo, or impact.

## When To Use It

Run the gate before writing a report. Do not draft a bounty submission until it
returns `submit`, or the `defer` evidence gaps are resolved.

The value is not "we found every bug." The value is telling you which
scary-looking control-plane reports are real, which are missing evidence, and
which will turn into bounty-triage noise — before:

- launching a bounty;
- entering an audit contest;
- shipping a bridge or OApp;
- upgrading a proxy/admin path;
- moving Safe, timelock, oracle, mint, vault, or withdrawal controls.

## Current Limits

This first version is heuristic. It parses plain text and Markdown scope pages,
then applies conservative reportability scoring. It does not scrape bounty
platforms, authenticate to private programs, verify commits, or run chain/RPC
proofs by itself.

Use it as a gate before deeper source review and PoC work.
