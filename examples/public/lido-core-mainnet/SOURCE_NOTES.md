# Lido Core Mainnet Fixture Notes

This is a ProtocolGate public case-study fixture, not a live-state assertion and not an audit of Lido.

Public repo cloned locally:

- Source: `https://github.com/lidofinance/core`
- Local path: `.research/repos/lido-core`
- Shallow clone HEAD used for this fixture: `eb4ff80`

Source files used:

- `deployed-mainnet.json` for Aragon Agent, Aragon Voting, Lido app proxy, AccountingOracle proxy, and WithdrawalQueue addresses.
- `contracts/0.4.24/Lido.sol` for pause/resume and role-controlled protocol surfaces.
- `contracts/0.8.9/WithdrawalQueue.sol` for withdrawal queue pause/resume surfaces.
- `contracts/0.4.24/template/LidoTemplate.sol` and `contracts/upgrade/V3Template.sol` for Aragon permission and upgrade flow context.

Modeled ProtocolGate interpretation:

- Lido's Aragon voting plus Agent execution path is represented as `LidoDAOExecution`, a delayed governance control path. It is not a claim that Aragon Agent is literally an EVM timelock contract.
- The `LidoGateSeal` guardian entry is included as a named emergency/security actor, but this fixture intentionally does not enumerate signer sets.
- The proposal intent entry is representative and exists to exercise CG032-CG038 against an app-upgrade control path. It is not claiming to be a real historical proposal.
