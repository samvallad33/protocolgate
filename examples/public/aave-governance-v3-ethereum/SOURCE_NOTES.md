# Aave Governance V3 Ethereum Fixture Notes

This is a ProtocolGate public case-study fixture, not a live-state assertion and not an audit of Aave.

Public repo cloned locally:

- Source: `https://github.com/aave-dao/aave-governance-v3`
- Local path: `.research/repos/aave-governance-v3`
- Shallow clone HEAD used for this fixture: `5b240b1`

Source files used:

- `deployments/ethereum.json` for governance, executor, payload controller, proxy admin, guardian, and cross-chain controller addresses.
- `docs/overview.md` for the core network, voting network, execution network, proposal lifecycle, owner, guardian, and payload execution model.
- `docs/properties.md` for queued proposal and payload execution invariants.
- `src/contracts/Governance.sol` for default voting delay and voting duration values.
- `src/contracts/payloads/PayloadsControllerCore.sol` for execution delay bounds and payload lifecycle constants.

Modeled ProtocolGate interpretation:

- Aave Level 1 and Level 2 executors are represented as timelock-like delayed admin control paths.
- The manifest models high-level governance and payload execution topology, not every deployed Aave peripheral contract.
- The proposal intent entry is representative and exists to exercise CG032-CG038 against a governance payload execution path. It is not claiming to be a real historical proposal.
