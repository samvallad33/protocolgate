"""On-chain snapshot collector.

Turns a target's deployed addresses into the ``snapshot.json`` shape that
``drift.compare_snapshot`` consumes, by reading **live chain state** over a
standard JSON-RPC endpoint.

Design constraints (load-bearing):
- Read-only. Only ``eth_getStorageAt`` and ``eth_call`` are used.
- No private keys, no transactions, no signing.
- Dependency-free (urllib only) so the policy gate is not bound to a provider.
- Deterministic output shape:
  ``{"contracts": [{"name", "address", "proxy": {"admin"}}],
     "multisigs": [{"name", "address", "threshold"}]}``

The collector is the moat: drift only exists relative to live state, and static
fortresses pay $0. Everything downstream (drift → capsule → fork PoC) is glue.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

# EIP-1967 admin slot: bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1)
EIP1967_ADMIN_SLOT = (
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
)
# EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
EIP1967_IMPL_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
# Gnosis Safe getThreshold() selector = bytes4(keccak256("getThreshold()"))
SAFE_GET_THRESHOLD_SELECTOR = "0xe75235b8"

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


class CollectorError(RuntimeError):
    """Raised when the RPC endpoint cannot be reached or returns malformed data."""


@dataclass(frozen=True)
class ContractTarget:
    name: str
    address: str
    is_proxy: bool = True


@dataclass(frozen=True)
class MultisigTarget:
    name: str
    address: str


@dataclass(frozen=True)
class CollectionResult:
    """The snapshot plus a per-subject error log (collection never half-lies)."""

    snapshot: dict[str, Any]
    errors: list[str] = field(default_factory=list)


class RpcClient:
    """Minimal, read-only JSON-RPC client. Never signs, never sends value."""

    def __init__(self, rpc_url: str, timeout: float = 15.0) -> None:
        if not rpc_url:
            raise CollectorError("rpc_url is required")
        self.rpc_url = rpc_url
        self.timeout = timeout
        self._id = 0

    def _call(self, method: str, params: list[Any]) -> Any:
        # Hard guard: this client is read-only by construction. Refuse any method
        # that could mutate chain state or expose keys, even if asked.
        if not (method.startswith("eth_") or method == "net_version"):
            raise CollectorError(f"refused non-read RPC method: {method}")
        if method in {"eth_sendTransaction", "eth_sendRawTransaction", "eth_sign"}:
            raise CollectorError(f"refused state-changing/signing method: {method}")

        self._id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        ).encode("utf-8")
        request = urllib.request.Request(
            self.rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            raise CollectorError(f"rpc call {method} failed: {exc}") from exc

        if isinstance(data, dict) and data.get("error"):
            raise CollectorError(f"rpc error on {method}: {data['error']}")
        if not isinstance(data, dict) or "result" not in data:
            raise CollectorError(f"malformed rpc response for {method}")
        return data["result"]

    def get_storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        return self._call("eth_getStorageAt", [address, slot, block])

    def eth_call(self, to: str, data: str, block: str = "latest") -> str:
        return self._call("eth_call", [{"to": to, "data": data}, block])


def _word_to_address(word: str) -> str | None:
    """Right-most 20 bytes of a 32-byte storage word → checksum-agnostic address."""
    if not word:
        return None
    h = word[2:] if word.startswith("0x") else word
    if len(h) < 40:
        return None
    addr = "0x" + h[-40:]
    if addr.lower() == ZERO_ADDRESS:
        return None
    return addr.lower()


def _hex_to_int(value: str) -> int | None:
    try:
        return int(value, 16)
    except (TypeError, ValueError):
        return None


def collect_proxy_admin(
    client: RpcClient, address: str, block: str = "latest"
) -> str | None:
    """Read the EIP-1967 admin slot for a transparent/UUPS proxy."""
    word = client.get_storage_at(address, EIP1967_ADMIN_SLOT, block)
    return _word_to_address(word)


def collect_safe_threshold(
    client: RpcClient, address: str, block: str = "latest"
) -> int | None:
    """Read a Gnosis Safe's signature threshold via getThreshold()."""
    word = client.eth_call(address, SAFE_GET_THRESHOLD_SELECTOR, block)
    return _hex_to_int(word)


def collect_snapshot(
    rpc_url: str,
    contracts: list[ContractTarget],
    multisigs: list[MultisigTarget],
    block: str = "latest",
    timeout: float = 15.0,
) -> CollectionResult:
    """Collect a live-state snapshot in the shape ``compare_snapshot`` expects.

    Failures are recorded per-subject in ``errors`` rather than aborting the whole
    run, so one dead address never silently zeroes the entire snapshot (which would
    masquerade as catastrophic drift).
    """

    client = RpcClient(rpc_url, timeout=timeout)
    errors: list[str] = []
    out_contracts: list[dict[str, Any]] = []
    out_multisigs: list[dict[str, Any]] = []

    for c in contracts:
        entry: dict[str, Any] = {"name": c.name, "address": c.address}
        if c.is_proxy:
            try:
                admin = collect_proxy_admin(client, c.address, block)
                entry["proxy"] = {"admin": admin}
            except CollectorError as exc:
                errors.append(f"contract {c.name} ({c.address}): {exc}")
                # Omit proxy key entirely on error so drift treats it as
                # "missing", not "changed to null" (a false critical).
        out_contracts.append(entry)

    for m in multisigs:
        entry = {"name": m.name, "address": m.address}
        try:
            threshold = collect_safe_threshold(client, m.address, block)
            entry["threshold"] = threshold
        except CollectorError as exc:
            errors.append(f"multisig {m.name} ({m.address}): {exc}")
        out_multisigs.append(entry)

    snapshot = {
        "block": block,
        "contracts": out_contracts,
        "multisigs": out_multisigs,
    }
    return CollectionResult(snapshot=snapshot, errors=errors)


def targets_from_manifest(manifest: dict[str, Any]) -> tuple[
    list[ContractTarget], list[MultisigTarget]
]:
    """Derive collection targets from a protocolgate manifest.

    A manifest contract is treated as a proxy if it declares a ``proxy`` block.
    Only entries with an ``address`` are collectable (the collector needs a live
    address to read; name-only manifest rows are skipped).
    """

    contracts: list[ContractTarget] = []
    for c in manifest.get("contracts", []):
        name = c.get("name")
        address = c.get("address")
        if not name or not address:
            continue
        contracts.append(
            ContractTarget(name=name, address=address, is_proxy=bool(c.get("proxy")))
        )

    multisigs: list[MultisigTarget] = []
    for m in manifest.get("multisigs", []):
        name = m.get("name")
        address = m.get("address")
        if not name or not address:
            continue
        multisigs.append(MultisigTarget(name=name, address=address))

    return contracts, multisigs
