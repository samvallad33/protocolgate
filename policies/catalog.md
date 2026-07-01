# ProtocolGate Policy Catalog

ProtocolGate policies are Web3 control-plane invariants, not generic lint rules.
The first pack focuses on deployment topology and privileged-operation controls
that show up repeatedly in smart-contract audit findings and protocol reviews.

| Rule | Status | Control |
| --- | --- | --- |
| CG001 | Implemented | Upgradeable contracts require a 24h+ timelocked governance controller. |
| CG002 | Implemented | Proxy admin must not be an EOA. |
| CG003 | Implemented | Admin-only functions require a 24h+ timelock. |
| CG004 | Implemented | Redemption paths require cooldown, circuit breaker, and pause controls. |
| CG005 | Implemented | Token, oracle, and accounting decimals must align. |
| CG006 | Implemented | Bridge contracts require per-block rate limits. |
| CG007 | Implemented | Oracle staleness windows must be bounded. |
| CG008 | Implemented | Oracle failures must fail closed. |
| CG009 | Implemented | Treasury splits must be complete and sum to 10000 bps. |
| CG010 | Implemented | Multisig thresholds must reject paper multisigs and impossible thresholds. |
| CG011 | Implemented | Unpause must route through timelock governance. |
| CG012 | Implemented | External calls require checks-effects-interactions and nonReentrant protection. |
| CG013 | Implemented | Upgradeable contracts require storage layout checks. |
| CG014 | Implemented | Upgradeable implementations must lock initializers. |
| CG015 | Implemented | Privileged mint and burn functions require caps. |
| CG016 | Implemented | Privileged supply controls require timelock governance. |
| CG017 | Implemented | Production deploys must pin chain ID. |
| CG018 | Implemented | Production deploys must declare allowed deployers. |
| CG019 | Implemented | Pause and upgrade authorities must be separated. |
| CG020 | Implemented | Fee changes require hard maximum bounds. |
| CG021 | Implemented | Fee changes require timelock governance. |
| CG022 | Implemented | Upgrade guardians require timelocks. |
| CG023 | Implemented | Pause guardians require multisig backing. |
| CG024 | Implemented | Governance requires a quorum floor. |
| CG025 | Implemented | Governance voting periods require a 24h floor. |
| CG026 | Implemented | Security actor references must resolve to declared multisigs, governors, timelocks, or guardians. |
| CG027 | Planned | Cross-chain message senders must be domain-separated. |
| CG028 | Planned | Liquidation parameters must preserve solvency under configured stress bands. |
| CG029 | Planned | Reward emission schedules must have hard end dates or decay curves. |
| CG030 | Planned | Vault share price updates must be monotonic unless explicitly loss-realizing. |
| CG031 | Planned | Cross-contract identity assumptions must be declared for delegatecall and module systems. |
| CG032 | Implemented | Privileged proposals require signer-readable metadata. |
| CG033 | Implemented | Privileged proposals must have bounded validity; no indefinite pre-signed approvals. |
| CG034 | Implemented | Executed calldata hash must match reviewed proposal calldata hash. |
| CG035 | Implemented | Upgrade/admin/oracle/bridge/treasury selectors must be allowlisted. |
| CG036 | Implemented | Safe/Squads modules and guards must be declared and allowlisted. |
| CG037 | Implemented | High-privilege proposals require transaction simulation before signing. |
| CG038 | Implemented | Admin-transfer, oracle-change, bridge-limit, mint-cap, and withdrawal-limit proposals require monitor coverage. |
| CG039 | Implemented (hunt) | Safety-control scope must cover every state component used by the protected predicate. |
| CG040 | Planned | Replacement safety controls must be at least as broad as removed guards unless explicitly accepted. |
| CG041 | Planned | User-protection grace windows must block alternate execution paths that consume user funds. |
| CG042 | Planned | Pause/unpause recovery windows must be modeled as account-affecting when account health is global. |
| CG043 | Planned | Existing storage variables must not move slots or offsets during upgrades. |
| CG044 | Planned | Existing storage variable types must not change incompatibly during upgrades. |
| CG045 | Planned | Removed storage variables require explicit tombstones or rename maps. |
| CG046 | Planned | New storage variables must append after the old layout tail. |
| CG047 | Planned | Storage gaps must not be over-consumed. |
| CG048 | Planned | Upgradeable inheritance chains should preserve storage gaps. |
| CG049 | Planned | Proxy upgrade targets must have available storage layout artifacts. |
| CG050 | Planned | Upgrade migration initializers require explicit intent and simulation evidence. |
| CG051 | Planned | Implementation contracts must not be directly initializable. |
| CG052 | Planned | UUPS targets must preserve ERC1967/proxiableUUID expectations. |
