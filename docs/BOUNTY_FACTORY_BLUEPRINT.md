# ProtocolGate — The 1-of-1 Blueprint

> Web-verified completion spec (2026 research). The drift-trigger → fork-verified-PoC →
> memory-as-router loop, where memory changes the next action and value-weights the
> scan budget. This is the part competitors cannot assemble from public parts.

## The white space (the moat, stated crisply)

A closed loop where:
- **on-chain control-plane drift is the TRIGGER**,
- **a real fork-and-execute PoC is the VERIFIER**, and
- **a trust-weighted, supersession-aware, FSRS-decayed cross-bounty memory is the ROUTER**
  that decides where to spend scan budget — compounding across every engagement.

The load-bearing word is **ROUTER, not store.** The novelty is not that Vestige
*remembers* findings (Pensyve/Zep/Mem0 can). It is that memory **changes the next
action**: DEAD_DOOR skips before a PoC run, PRIOR_WIN value-weights priority,
DUPLICATE_RISK kills already-claimed bounties before submission, HISTORICAL_EXPLOIT
arms the template. `evidence → implication → action`.

**Why it's economically defensible (A1 paper):** attackers have a ~10x scan-budget
advantage ($100K exploit funds ~33,000 scans; a 10% bounty funds ~3,300). You cannot
win on compute or model quality — everyone has the same frontier models. The only
counter is spending limited scans where prior memory says payoff is highest and
skipping proven dead doors. **Memory is the literal economic answer to the attacker's
10x advantage.**

## The bright line (never violate)
- **Never auto-promote to submission-ready.** The verifier gates *eligibility*; a human submits.
- **Fork tests only.** All exploit execution is `createSelectFork` against an archive RPC at the drift block, in Docker. No mainnet transactions.
- **No keys.** Read-only RPC + local Foundry. The "exploit" proves a balance/state delta on a fork, nothing more.

## The thesis (north star — every build decision serves this)

Three pillars, and the architecture must serve all three:

1. **Compounding data moat.** Scanners, fuzzers, even FSRS memory engines (Pensyve) are
   copyable. An *algorithmic routing engine trained on cross-bounty history* is not — the
   moat is `algorithm × time × accumulated private data`. A newcomer copies the code but
   starts at zero history. The more it runs, the cheaper and smarter it gets; the moat
   **widens** instead of eroding.
2. **Economic superiority.** Shift off the commodity arms race ("best fuzzer/model/detector?")
   onto **"lowest cost-per-bug-found?"** The A1 paper proves it: attackers have ~10x the scan
   budget, so raw compute is a losing game for defenders. Routing is the only lever that
   changes unit economics. Saving 90% of compute while holding coverage is a P&L line.
3. **Timing.** 2026 is flooded with commoditized AI auditors; users have alert/tool fatigue.
   The market needs an **orchestrator to kill the noise**, not a 50th detector. ProtocolGate
   is the layer that decides which of the other 49 are worth listening to. A category, not a product.

**Architectural consequence (load-bearing):** because the moat is *cost-per-bug*, CORE-0's
router must track its **own economics as a first-class metric** — every run records scans
spent, scans **skipped** (dead-doors avoided), and realized USD per scan. The falling
`cost_per_finding` over time **is the moat made visible**: the demo, the sales chart, and
the regression test in one. Build this counter into the router from day one.

## CORE builds (priority order)

### CORE-1 — Real fork-and-execute verifier  ← BUILD FIRST
Replaces the `sha256(expected)!=sha256(actual)` placeholder in `bounty_sim.py`.
- **Generation:** LLM PoC loop (PoCo/ReX pattern): generate `exploit.sol` + test → `forge build` → `forge test -vvvv` → on failure feed stderr back, cap ~4 iters.
- **Ground-truth oracle (A1):** report only on a *measured* balance/state delta on `createSelectFork` at the drift block, normalized to USD. Execution is the only oracle — no LLM judging itself.
- **Patch-as-oracle (PoCo):** when a mitigation patch exists, PoC must pass on vulnerable code and fail on patched.
- **Fuzzer fallback:** when a single-shot PoC stalls (cross-contract, accumulated-rounding, deep-stateful), fall back to **ItyFuzz** on the exact forked state: `ETH_RPC_URL=<rpc> ityfuzz evm -t <addrs> -c <chain> --flashloan --onchain-block-number <drift_block>`. (Olympia 147/200; +44% vs Echidna.)
- **Memorization guard (A1 masked-variant):** strip function bodies, re-run detection; survives → reasoning, not training recall.
- **Seam:** `bounty_sim.py` emits passing test + measured USD impact into the `VerdictCapsule`; `factory.py` uses the verifier result as the objective gate for submission-ready *eligibility* (still human-confirmed). `smart_ingest` the capsule back to Vestige.
- Why not a moat: A1/PoCo/EVMbench/ReX all do this; ItyFuzz/Medusa/Halmos are commodity. **Price of entry, not an advantage** — so build it solid and cheap.

### CORE-2 — Historical-bug recall feeding reasoning.py (inputs only)
- **Solodit API (Cyfrin):** `POST https://solodit.cyfrin.io/api/v1/solodit/findings`, header `X-Cyfrin-API-Key`. Map the 6 drift types → tag sets (proxy-admin → Access Control+Admin+Proxy; threshold → Quorum+DAO; oracle → Oracle+Stale Price). Fold Quality+Rarity into the trust chain. Cache (search 5min / finding 1h).
- **DeFiHackLabs:** ~725 runnable `createSelectFork` PoCs (MIT) → `{date, project, tag, poc_path, fork_block}` index → armable template bank for CORE-1 seeds.
- **Critical framing:** Cyfrin markets Solodit "to power AI security agents" — it is a public utility, **zero relative edge as a feature.** Wire it, never market it. The moat is dual-writing strong matches into Vestige so the *private* trust-weighted layer compounds on the *public* corpus.
- **Seam:** `connectors/solodit.py` + `historical_db.py`; `reasoning.py` fires Solodit on HISTORICAL_EXPLOIT / DUPLICATE_RISK; top match → CORE-1 seed; finding IDs → Vestige.

### CORE-0 — Memory-as-Router + cross-bounty invariant mining  ← THE MOAT
- **Router:** wrap `reasoning.py`'s 4 intents in a `BudgetDecision {action: skip|prioritize|arm|flag, weight, evidence}` that `factory.py` honors *before* any PoC run. `skip` = no fork run; `weight` = queue order, value-weighted by CORE-1's realized USD impact.
- **Vestige-backed invariant mining (Trace2Inv-on-memory):** mine candidate invariants from a *protocol family's* accumulated bounty history in Vestige → emit Foundry/Chimera invariant contract → feed CORE-1's fuzzer. Trace2Inv: 18–23/27 exploits blocked at 0.32% FP, but only per-contract; **cross-protocol-family mined invariants fused with a trust-weighted memory graph is the one capability that is novel AND requires Vestige to exist.** Cannot be cloned by bolting Solodit+Foundry onto an LLM.
- **Seam:** `reasoning.py::route()` → `BudgetDecision`; new `invariant_miner.py`; every verifier result (success AND fail, with USD impact) dual-writes via `smart_ingest` so routing + invariant corpus compound.

### CORE-3 — Live drift-trigger feed (event-driven)
- **OZ Monitor** (AGPL OSS, self-hosted — OZ Defender SaaS retires Jul 1 2026) watches `OwnershipTransferred` / `RoleGranted` / proxy-impl-changed on the `targets.yaml` watchlist → webhook → FastAPI receiver → `collector.py` snapshot → `drift.py` → enqueue into `factory.py`.
- **Why:** A1 detection-speed economics — immediate analysis = 86–89% chance of beating the attack window; 1-day delay → 7.6–27%; 7-day → 5.9–21%.
- Table-stakes infra; use the free OSS one, don't chase Tenderly paid.

## Cut (and why)
- Drift-type breadth parity (Hypernative 200-300, Hexagate 98% pre-hack) — never out-detect the vendors; add only highest-frequency-exploit drift types (role/access-control, oracle staleness, timelock, withdrawal-queue/bridge) as storage-slot/detector reads.
- pgvector/RAG memory rebuilds — Vestige already beats a bolted-on store.
- Mechanism envy (Pensyve/Zep/Mem0) — FSRS+temporal-KG is commodity; market the domain + assembled circle, not the mechanism.
- Manticore (archived), Mythril (legacy), Tenderly (paid), De.Fi/Rekt (no API).

## Defensive watch (not a build)
- **Pensyve** — Rust/Apache-2.0/FSRS/KG/MCP, a mechanism-level Vestige clone. If it pivots to security, half the "un-copyable" claim erodes. #1 watch.
- **Octane** — continuous PR/commit review. If it adds on-chain drift + memory, the wedge narrows.
- **Positioning vs Octane:** *"Octane audits the code on every commit; ProtocolGate watches who can change the deployed code, proves the exploit when they do, and remembers it across every bounty."*

## Build sequence (next 1-2 sessions)
1. **CORE-1 fork-and-execute verifier** (FIRST — fixes the credibility-killer placeholder; every other piece needs a real verdict signal).
2. **CORE-2** Solodit connector + DeFiHackLabs index (gives CORE-1 seeds + DUPLICATE_RISK).
3. **CORE-0 router** (BudgetDecision; where the moat starts paying).
4. **CORE-3** OZ Monitor webhook (event-driven).
5. **CORE-0 invariant mining** (highest ceiling, build last — consumes the compounding corpus the earlier steps fill).
