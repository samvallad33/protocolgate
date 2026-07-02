# ProtocolGate

**Audits check your code. ProtocolGate checks the control plane around it — in CI, before you deploy.**

Most crypto isn't stolen through code bugs. It's stolen through the **control plane**: admin keys, multisigs, timelocks, and signing flows. Bybit lost $1.5B because signers approved calldata that didn't match what their screen showed. The audited code was fine. The setup around it wasn't.

ProtocolGate catches that before you ship. You write your deployment setup in one file. It runs 34 checks in CI. If your control plane is unsafe, **the build fails** — nothing reaches mainnet.

```bash
uv run protocolgate validate protocolgate.yaml
```

It checks who can upgrade your proxy, whether your multisig is real or paper, whether your timelocks actually delay anything — and whether the calldata your signers approve matches what actually executes. All deterministic. No alerts, no guessing.

## The one that would've stopped Bybit

**CG034 — executed calldata must match reviewed intent.** Before anyone signs, the reviewed calldata is locked to a hash. At execution, the hash is checked again. If a single byte changed, the build fails. A signer can't approve something they never actually saw. That's the $1.5B blind-signing hole — closed in CI.

## Try it

```bash
# passes
uv run protocolgate validate examples/protocolgate.valid.yaml

# fails, and shows you why (as JSON or a readable report)
uv run protocolgate validate examples/protocolgate.invalid.yaml --output json
uv run protocolgate validate examples/protocolgate.invalid.yaml --output markdown
```

## The one file

```yaml
version: 1
deployment:
  chain_id: 1
  allowed_deployers: [ProtocolMultisig]
multisigs:
  - name: ProtocolMultisig
    threshold: 3
    signers: ["0x...", "0x...", "0x...", "0x...", "0x..."]
timelocks:
  - name: ProtocolTimelock
    delay_seconds: 172800   # 48h
    proposer: ProtocolMultisig
    executor: ProtocolMultisig
contracts:
  - name: Vault
    upgradeable: true
    proxy:
      admin: ProtocolTimelock   # not a personal wallet
```

Full example: [`examples/protocolgate.valid.yaml`](examples/protocolgate.valid.yaml).

## In CI

```yaml
- uses: actions/checkout@v4
- uses: your-org/protocolgate/action@main
  with:
    manifest: protocolgate.yaml
```

Fails the workflow on any finding, so an unsafe control plane can't deploy.

## What it checks

- **Upgrades** — proxy admin isn't a personal wallet; upgrade power sits behind a timelock
- **Multisigs** — no 1-of-N paper multisigs
- **Timelocks** — admin actions, unpause, and supply/fee changes actually wait
- **Signing** — reviewed calldata == executed calldata (CG034); selector + Safe-module allowlists
- **Assumptions** — oracle staleness, bridge limits, treasury splits add up, chain ID pinned
- **Drift** — compares a live snapshot against your file to catch changes after launch

Every finding is a named rule with a severity and a fix. Full list: [`policies/catalog.md`](policies/catalog.md).

## What it isn't

ProtocolGate **doesn't replace** audits, fuzzing, or monitoring — it covers the layer they miss. It checks the setup *you declare*, so it's only as good as your file. Today it validates that file, reports findings, and detects drift; it doesn't yet read live chain state for you.

That's the point: catch a bad control plane **early**, in CI, where fixing it is free.

## More

- **Proposal Intent Gate** — is this privileged proposal safe to sign? → [`docs/PROPOSAL_INTENT_GATE.md`](docs/PROPOSAL_INTENT_GATE.md)
- **Real examples** — Compound, Lido, Aave manifests → [`examples/public/`](examples/public/)
- **Readiness Review** for protocol teams → [`docs/CONTROL_PLANE_REVIEW_OFFER.md`](docs/CONTROL_PLANE_REVIEW_OFFER.md)

Apache 2.0 · [`LICENSE`](LICENSE)
