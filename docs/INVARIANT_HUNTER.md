# ProtocolGate Invariant Hunter

ProtocolGate now has a separate hunt mode:

```bash
uv run protocolgate hunt examples/protocolgate.aave-grace-bypass.yaml
uv run protocolgate hunt examples/protocolgate.aave-grace-bypass.yaml --output markdown
```

`validate` asks:

> Does the declared control plane satisfy deployment policy?

`hunt` asks:

> Where are the weird doors between declared safety controls and executable
> protocol paths?

## CG039: Safety-Control Scope Mismatch

The first hunt rule is `CG039`.

It flags safety controls whose scope is narrower than the predicate they claim
to protect.

This captures the Aave V3.7 liquidation-grace class:

```text
Safety control:
  liquidationGracePeriodUntil is reserve-scoped

Protected predicate:
  healthFactorBelowOne is account-scoped

Bypass surface:
  liquidationCall lets the liquidator select collateralAsset and debtAsset
```

If a graced reserve contributes to account-global liquidation eligibility, but
the grace check only looks at the selected collateral/debt pair, a liquidator may
route through non-graced assets.

## Manifest Shape

```yaml
predicates:
  - name: healthFactorBelowOne
    scope: account
    reads:
      - all_enabled_collateral
      - all_user_debt
    authorizes:
      - liquidationCall

safety_controls:
  - name: LiquidationGrace
    contract: AavePool
    state_variable: liquidationGracePeriodUntil
    scope:
      kind: reserve
      key: asset
    protects:
      - action: liquidationCall
        predicate: healthFactorBelowOne
        expected_scope: account
        loss_surface: user_principal
    bypass_selectors:
      - collateralAsset
      - debtAsset
```

## Output

`CG039` emits a critical finding when the loss surface is user principal or
protocol solvency:

```text
LiquidationGrace is reserve-scoped but protects account-scoped predicate
healthFactorBelowOne for liquidationCall; selectable bypass inputs:
collateralAsset, debtAsset
```

## Why Hunt Mode Is Separate

A scope mismatch is a high-value attack hypothesis, not always a deployment
blocker. It still needs proof:

- source references;
- local fork execution;
- economic impact;
- false-positive kill checks;
- bounty-specific severity framing.

So `hunt` does not replace `validate`. It creates candidate findings for deeper
PoC work.

## Next Steps

The next ProtocolGate layers should be:

- source ingestion and protocol graph;
- generated Foundry PoC scaffolds;
- governance proposal time-travel simulation;
- zombie role liveness checks;
- storage-layout upgrade preflight;
- bounty report packaging.
