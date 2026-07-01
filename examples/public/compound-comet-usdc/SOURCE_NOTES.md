# Compound III Comet USDC Fixture Notes

This is a ProtocolGate public case-study fixture, not a live-state assertion and not an audit of Compound.

Public repo used while building this fixture:

- Source: `https://github.com/compound-finance/comet`
- Shallow clone HEAD used for this fixture: `ed6ebcd`

Source files used:

- `deployments/mainnet/usdc/roots.json` for Comet, Configurator, Rewards, bridge/root addresses.
- `deployments/mainnet/usdc/configuration.json` for the USDC market governor, pause guardian, tokens, and price feeds.
- `src/deploy/Network.ts` for the deployment control flow that clones GovernorBravo, creates a timelock, transfers timelock admin to the governor, and transfers CometProxyAdmin ownership.
- `contracts/CometProxyAdmin.sol`, `contracts/Configurator.sol`, and `contracts/Comet.sol` for privileged upgrade/configuration surfaces.

Modeled ProtocolGate interpretation:

- `CompoundTimelock` is represented as the main production admin path for the USDC market.
- `CompoundGovernorBravo` is represented as the controller of that timelock.
- The proposal intent entry is a representative upgrade-control fixture so CG032-CG038 can exercise the governance-to-calldata binding path. It is not claiming to be a real historical proposal.
