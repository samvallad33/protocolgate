"""Tests for the read-only on-chain snapshot collector.

No network: a fake RPC client returns canned hex words so the collector logic is
verified deterministically.
"""

from __future__ import annotations

import pytest

from protocolgate import collector
from protocolgate.collector import (
    EIP1967_ADMIN_SLOT,
    SAFE_GET_THRESHOLD_SELECTOR,
    CollectorError,
    ContractTarget,
    MultisigTarget,
    collect_snapshot,
    targets_from_manifest,
)


class FakeRpc:
    """Stand-in for RpcClient with scripted responses keyed by (method, args)."""

    def __init__(self, storage=None, calls=None, raise_for=None):
        self.storage = storage or {}
        self.calls = calls or {}
        self.raise_for = raise_for or set()

    def get_storage_at(self, address, slot, block="latest"):
        if ("storage", address) in self.raise_for:
            raise CollectorError("boom")
        return self.storage.get((address, slot), "0x" + "0" * 64)

    def eth_call(self, to, data, block="latest"):
        if ("call", to) in self.raise_for:
            raise CollectorError("boom")
        return self.calls.get((to, data), "0x" + "0" * 64)


def _word_for_address(addr: str) -> str:
    return "0x" + "0" * 24 + addr.lower().replace("0x", "")


def test_constants_are_canonical():
    # Guard against accidental edits to the load-bearing slot/selector.
    assert EIP1967_ADMIN_SLOT == (
        "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
    )
    assert SAFE_GET_THRESHOLD_SELECTOR == "0xe75235b8"


def test_collect_proxy_admin_and_threshold(monkeypatch):
    admin = "0x1111111111111111111111111111111111111111"
    proxy = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    safe = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    fake = FakeRpc(
        storage={(proxy, EIP1967_ADMIN_SLOT): _word_for_address(admin)},
        calls={(safe, SAFE_GET_THRESHOLD_SELECTOR): "0x" + "0" * 63 + "3"},
    )
    monkeypatch.setattr(collector, "RpcClient", lambda *a, **k: fake)

    result = collect_snapshot(
        "http://rpc.local",
        contracts=[ContractTarget(name="Vault", address=proxy)],
        multisigs=[MultisigTarget(name="Gov", address=safe)],
    )

    assert result.errors == []
    assert result.snapshot["contracts"][0]["proxy"]["admin"] == admin
    assert result.snapshot["multisigs"][0]["threshold"] == 3


def test_zero_admin_becomes_none(monkeypatch):
    proxy = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    fake = FakeRpc(storage={})  # returns all-zero word
    monkeypatch.setattr(collector, "RpcClient", lambda *a, **k: fake)

    result = collect_snapshot(
        "http://rpc.local",
        contracts=[ContractTarget(name="Vault", address=proxy)],
        multisigs=[],
    )
    assert result.snapshot["contracts"][0]["proxy"]["admin"] is None


def test_rpc_error_omits_proxy_key_not_null(monkeypatch):
    # A failed read must NOT write proxy.admin=null (that would masquerade as a
    # critical "admin drifted to null"). It should omit the proxy key + log error.
    proxy = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    fake = FakeRpc(raise_for={("storage", proxy)})
    monkeypatch.setattr(collector, "RpcClient", lambda *a, **k: fake)

    result = collect_snapshot(
        "http://rpc.local",
        contracts=[ContractTarget(name="Vault", address=proxy)],
        multisigs=[],
    )
    assert "proxy" not in result.snapshot["contracts"][0]
    assert len(result.errors) == 1
    assert "Vault" in result.errors[0]


def test_targets_from_manifest_skips_addressless_rows():
    manifest = {
        "contracts": [
            {"name": "Vault", "address": "0xabc", "proxy": {"admin": "0xdead"}},
            {"name": "NoAddr"},  # skipped: not collectable
            {"name": "Plain", "address": "0xdef"},  # not a proxy
        ],
        "multisigs": [
            {"name": "Gov", "address": "0xfee", "threshold": 3},
            {"name": "NoAddr"},  # skipped
        ],
    }
    contracts, multisigs = targets_from_manifest(manifest)
    assert [c.name for c in contracts] == ["Vault", "Plain"]
    assert {c.name: c.is_proxy for c in contracts} == {"Vault": True, "Plain": False}
    assert [m.name for m in multisigs] == ["Gov"]


def test_rpc_client_refuses_state_changing_methods():
    from protocolgate.collector import RpcClient

    client = RpcClient("http://rpc.local")
    for bad in ("eth_sendTransaction", "eth_sendRawTransaction", "eth_sign"):
        with pytest.raises(CollectorError):
            client._call(bad, [])
    with pytest.raises(CollectorError):
        client._call("personal_unlockAccount", [])
