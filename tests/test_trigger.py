"""Tests for the event-driven drift trigger.

No network, no web server: every test feeds plain dicts to the pure normalizer
and router. Covers OZ-Monitor payload parsing (flat + nested envelope), the
control-plane event filter, address -> target mapping, and graceful degradation
on unknown / addressless / non-control-plane events.
"""

from __future__ import annotations

import pytest

from protocolgate.factory import FactoryTarget
from protocolgate.trigger import (
    DriftEvent,
    TriggerError,
    build_collector_invocation,
    build_targets_index,
    extract_drift_events,
    is_control_plane_event,
    parse_monitor_event,
)


PROXY = "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"
PROXY_LOWER = PROXY.lower()
SAFE = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
UNKNOWN = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


# --------------------------------------------------------------------------- #
# parse_monitor_event
# --------------------------------------------------------------------------- #


def _oz_monitor_payload() -> dict:
    """A representative OpenZeppelin Monitor / Defender Sentinel webhook shape.

    The interesting fields are nested under ``sentinel`` / ``transaction`` /
    ``matchReasons`` exactly as OZ delivers them, so the test pins that the
    normalizer flattens the envelope rather than only reading flat keys.
    """

    return {
        "type": "TX",
        "sentinel": {
            "id": "sentinel-1",
            "name": "Aave control-plane sentinel",
            "chainId": 1,
            "address": PROXY,
        },
        "transaction": {
            "transactionHash": (
                "0x" + "11" * 32
            ),
            "blockNumber": "0x12d687",  # hex block number
        },
        "matchReasons": [
            {
                "type": "event",
                "signature": "OwnershipTransferred(address,address)",
                "params": {
                    "previousOwner": "0x" + "0" * 39 + "1",
                    "newOwner": "0x" + "0" * 39 + "2",
                },
            }
        ],
    }


def test_parse_oz_monitor_payload_flattens_envelope():
    event = parse_monitor_event(_oz_monitor_payload())

    assert isinstance(event, DriftEvent)
    # Raw event name preserved with on-chain spelling/signature.
    assert event.event == "OwnershipTransferred(address,address)"
    # Address lowercased from the nested sentinel container.
    assert event.address == PROXY_LOWER
    assert event.chain_id == 1
    # Hex block number coerced to int.
    assert event.block == 0x12D687
    assert event.tx_hash == "0x" + "11" * 32
    # Original payload retained untouched for audit.
    assert event.raw["sentinel"]["address"] == PROXY


def test_parse_flat_generic_webhook():
    payload = {
        "event_name": "RoleGranted",
        "contract_address": SAFE,
        "chain_id": "8453",
        "block_number": 19_000_000,
        "tx_hash": "0xabc",
    }
    event = parse_monitor_event(payload)
    assert event.event == "RoleGranted"
    assert event.address == SAFE
    assert event.chain_id == 8453
    assert event.block == 19_000_000
    assert event.tx_hash == "0xabc"


def test_extract_oz_monitor_raw_events_array():
    payload = {
        "chainId": "1",
        "transaction": {
            "hash": "0x" + "22" * 32,
            "blockNumber": "19000000",
            "to": PROXY,
        },
        "events": [
            {
                "signature": "Transfer(address,address,uint256)",
                "address": PROXY,
            },
            {
                "signature": "RoleGranted(bytes32,address,address)",
                "address": SAFE,
            },
        ],
    }

    events = extract_drift_events(payload)

    assert len(events) == 2
    assert all(isinstance(event, DriftEvent) for event in events)
    assert events[0].event == "Transfer(address,address,uint256)"
    assert events[0].address == PROXY_LOWER
    assert events[0].chain_id == 1
    assert events[0].block == 19_000_000
    assert events[0].tx_hash == "0x" + "22" * 32
    assert events[1].event == "RoleGranted(bytes32,address,address)"
    assert events[1].address == SAFE


def test_parse_address_without_0x_prefix_is_normalized():
    event = parse_monitor_event(
        {"event": "Upgraded", "address": PROXY_LOWER[2:]}
    )
    assert event.address == PROXY_LOWER


def test_parse_rejects_non_mapping():
    with pytest.raises(TriggerError):
        parse_monitor_event(["not", "a", "dict"])  # type: ignore[arg-type]


def test_parse_rejects_empty_unroutable_payload():
    with pytest.raises(TriggerError):
        parse_monitor_event({"foo": "bar", "block": 1})


def test_parse_tolerates_missing_optional_fields():
    # Event name + address present, everything else absent -> no crash, Nones.
    event = parse_monitor_event({"event": "Paused", "address": PROXY})
    assert event.event == "Paused"
    assert event.address == PROXY_LOWER
    assert event.chain_id is None
    assert event.block is None
    assert event.tx_hash == ""


# --------------------------------------------------------------------------- #
# is_control_plane_event
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name",
    [
        "OwnershipTransferred",
        "OwnershipTransferred(address,address)",
        "ownership_transferred",
        "Ownership Transferred",
        "RoleGranted",
        "RoleRevoked",
        "RoleAdminChanged",
        "AdminChanged",
        "Upgraded",
        "BeaconUpgraded",
        "ChangedThreshold",
        "AddedOwner",
        "RemovedOwner",
        "EnabledModule",
        "Paused",
        "Unpaused",
        "GuardianChanged",
    ],
)
def test_control_plane_events_fire(name):
    assert is_control_plane_event(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "Transfer",
        "Approval",
        "Swap",
        "Deposit",
        "Withdraw",
        "Sync",
        "Mint",  # token mint is data-plane here, not a control change
        "",
        "   ",
        "1234",
    ],
)
def test_data_plane_events_do_not_fire(name):
    assert is_control_plane_event(name) is False


def test_control_plane_handles_non_string():
    assert is_control_plane_event(None) is False  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# build_collector_invocation — address -> target mapping + degradation
# --------------------------------------------------------------------------- #


def _target() -> FactoryTarget:
    return FactoryTarget(
        name="Aave Governance V3",
        chain="ethereum-mainnet",
        manifest="examples/public/aave/protocolgate.yaml",
        rpc_url_env="ETH_RPC_URL",
    )


def test_known_address_control_plane_event_invokes():
    target = _target()
    index = {PROXY_LOWER: target}
    event = parse_monitor_event({"event": "Upgraded", "address": PROXY})

    inv = build_collector_invocation(event, index)

    assert inv["invoke"] is True
    assert inv["reason"] == "control-plane-drift"
    assert inv["target"] is target
    assert inv["target_name"] == "Aave Governance V3"
    assert inv["address"] == PROXY_LOWER
    assert inv["event"] == "Upgraded"
    assert inv["pipeline"] == [
        "collect_snapshot",
        "compare_snapshot",
        "factory_enqueue",
    ]


def test_known_address_non_control_plane_event_degrades():
    target = _target()
    index = {PROXY_LOWER: target}
    event = parse_monitor_event({"event": "Transfer", "address": PROXY})

    inv = build_collector_invocation(event, index)

    # We own the address, but a Transfer does not justify spending a scan.
    assert inv["invoke"] is False
    assert inv["reason"] == "not-control-plane"
    assert inv["target"] is target  # still resolved for logging


def test_unknown_address_degrades_to_noop():
    index = {PROXY_LOWER: _target()}
    event = parse_monitor_event({"event": "OwnershipTransferred", "address": UNKNOWN})

    inv = build_collector_invocation(event, index)

    assert inv["invoke"] is False
    assert inv["reason"] == "unknown-address"
    assert inv["target"] is None
    assert inv["target_name"] == ""


def test_missing_address_degrades_to_noop():
    # Control-plane event with no address (e.g. a contract-less alert).
    event = DriftEvent(event="OwnershipTransferred", address="")
    inv = build_collector_invocation(event, {PROXY_LOWER: _target()})
    assert inv["invoke"] is False
    assert inv["reason"] == "no-address"


def test_index_lookup_is_case_insensitive():
    # Index keyed by mixed-case address; event normalized to lowercase. The
    # router must still resolve it.
    target = _target()
    index = {PROXY: target}  # mixed-case key
    event = parse_monitor_event({"event": "AdminChanged", "address": PROXY_LOWER})

    inv = build_collector_invocation(event, index)
    assert inv["invoke"] is True
    assert inv["target"] is target


def test_empty_index_degrades():
    event = parse_monitor_event({"event": "Upgraded", "address": PROXY})
    inv = build_collector_invocation(event, {})
    assert inv["invoke"] is False
    assert inv["reason"] == "unknown-address"


# --------------------------------------------------------------------------- #
# build_targets_index — joins targets.yaml paths to manifest addresses
# --------------------------------------------------------------------------- #


def test_build_targets_index_maps_all_manifest_addresses():
    target = _target()
    manifest = {
        "contracts": [
            {"name": "Vault", "address": PROXY, "proxy": {"admin": "0xdead"}},
            {"name": "NoAddr"},  # skipped
        ],
        "multisigs": [
            {"name": "Gov", "address": SAFE, "threshold": 3},
        ],
        "timelocks": [
            {"name": "TL", "address": "0x" + "c" * 40},
        ],
    }
    index = build_targets_index([target], {target.manifest: manifest})

    assert index[PROXY_LOWER] is target
    assert index[SAFE] is target
    assert index["0x" + "c" * 40] is target
    assert len(index) == 3  # NoAddr skipped


def test_build_targets_index_skips_targets_without_loaded_manifest():
    target = _target()
    # Manifest path not provided in the manifests map -> target contributes
    # nothing rather than crashing.
    index = build_targets_index([target], {})
    assert index == {}


def test_build_targets_index_then_route_end_to_end():
    target = _target()
    manifest = {"contracts": [{"name": "Vault", "address": PROXY}]}
    index = build_targets_index([target], {target.manifest: manifest})

    event = parse_monitor_event(_oz_monitor_payload())
    inv = build_collector_invocation(event, index)

    assert inv["invoke"] is True
    assert inv["target"] is target
    assert inv["reason"] == "control-plane-drift"
