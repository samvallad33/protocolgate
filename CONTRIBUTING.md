# Contributing to ProtocolGate

Thanks for your interest in ProtocolGate — an open-source Web3 control-plane
policy gate. Contributions are welcome, whether that's a new control rule, a
bug fix, better docs, or a real-world manifest fixture.

## Ground rules

- ProtocolGate's rules are **deterministic**. No LLM or nondeterministic logic
  belongs in the decision path — a finding must be reproducible from the
  manifest alone.
- Rules should be **honest about scope**. ProtocolGate checks the declared
  control plane; it does not audit Solidity, query live RPC, or replace formal
  verification. Keep new features inside that wedge or clearly mark them as
  advisory.
- Prefer **narrow, well-named controls** with a stable rule ID, a clear
  severity, a path, and remediation guidance over broad heuristics.

## Development setup

ProtocolGate uses [uv](https://github.com/astral-sh/uv) and targets Python
3.11+.

```bash
# Install dependencies and run the CLI from a checkout
uv run protocolgate validate examples/protocolgate.valid.yaml

# Run the test suite
uv run pytest

# Optional: lint with ruff (ephemeral, no install needed)
uvx ruff check src/
```

## Adding a control rule

1. Implement the rule in the appropriate `src/protocolgate/rules_*.py` module
   and register it in the evaluator list in `src/protocolgate/rules.py`.
2. Give it a stable `CGxxx` ID and add it to `policies/catalog.md`.
3. Add both a passing and a failing fixture under `examples/` and cover the
   rule with a test in `tests/`.
4. Keep the message signer-readable: say what is wrong, where, and what to do.

## Pull requests

- Keep PRs focused and describe the control-plane risk the change addresses.
- Include tests. CI (`.github/workflows/protocolgate.yml`) runs the suite, the
  example manifests, and the build.
- By contributing, you agree your contributions are licensed under the
  project's [Apache-2.0](LICENSE) license.

## Reporting security issues

Please do **not** file public issues for vulnerabilities — see
[SECURITY.md](SECURITY.md).
