"""Event-driven drift trigger.

This module turns a *control-plane event* (an OpenZeppelin Monitor / Defender
webhook, or any generic webhook carrying an event name + contract address) into
the arguments needed to fire one scan: collect a live snapshot for the affected
target, drift it against its manifest, and enqueue the result in the factory.

The whole point of the trigger is to make the moat *event-driven* instead of
poll-driven: scans cost money, so we only pay for one when an on-chain control
event suggests the topology may have drifted. An ``OwnershipTransferred`` /
``RoleGranted`` / ``Upgraded`` on a watched address is exactly the cheap signal
that justifies spending a scan; a swap or a transfer is not.

Design constraints (load-bearing, match the rest of the repo):

- Pure + stdlib only. NO web-server framework dependency in this module. It is a
  normalizer and a router, importable and unit-testable with plain dicts. The
  HTTP listener that calls :func:`parse_monitor_event` lives elsewhere (CLI /
  connector) so this stays a function of ``payload -> DriftEvent``.
- Frozen dataclasses, ``from __future__`` annotations, stdlib-first style.
- Degrade gracefully. A malformed payload raises a typed
  :class:`TriggerError`; an *unknown* address is NOT an error -- it degrades to
  a no-op invocation (``invoke=False``) so a noisy webhook stream never crashes
  the loop and never scans an address we do not own.
- BRIGHT LINE preserved downstream: this module only ever *enqueues* a
  collect -> drift -> factory pass. It never submits, never signs, holds no keys.
  The factory it feeds still never auto-promotes to submission-ready.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------- #
# Control-plane event vocabulary
# --------------------------------------------------------------------------- #
# These are the events worth paying for a scan over: they change *who* controls
# the protocol or *what code* runs, i.e. exactly the control-plane topology the
# manifest pins. A token transfer or a swap changes balances, not control, and
# must NOT fire a scan.
#
# Matching is done on a normalized event name (lowercased, non-alphanumerics
# stripped) so "OwnershipTransferred", "ownership_transferred", and
# "Ownership Transferred" all collapse to the same token. We match on
# substrings so chain/proxy-specific variants ("AdminChanged",
# "BeaconUpgraded", "RoleAdminChanged") are caught without an exhaustive list.
CONTROL_PLANE_MARKERS: tuple[str, ...] = (
    # ownership
    "ownershiptransferred",
    "ownershiptransferstarted",  # Ownable2Step
    "ownerchanged",
    "newowner",
    # access-control roles
    "rolegranted",
    "rolerevoked",
    "roleadminchanged",
    "adminchanged",  # EIP-1967 ProxyAdmin / TransparentUpgradeableProxy
    "newadmin",
    # upgrades / implementation swaps
    "upgraded",
    "upgrade",
    "beaconupgraded",
    "implementationset",
    "implementationchanged",
    "newimplementation",
    # multisig / threshold / signer policy (Gnosis Safe control plane)
    "changedthreshold",
    "thresholdchanged",
    "addedowner",
    "removedowner",
    "enabledmodule",
    "disabledmodule",
    "changedguard",
    "changedfallbackhandler",
    # timelock / delay / guardian policy
    "mindelaychange",
    "delaychange",
    "guardianchanged",
    "pauserchanged",
    "paused",
    "unpaused",
)

# Payload keys (across OZ Monitor, Defender, and generic webhooks) that may hold
# the event name. Checked in order; first non-empty wins.
_EVENT_NAME_KEYS: tuple[str, ...] = (
    "eventType",
    "event_type",
    "event",
    "eventName",
    "event_name",
    "name",
    "signature",
    "eventSignature",
    "type",
)

# Payload keys that may hold the affected contract address.
_ADDRESS_KEYS: tuple[str, ...] = (
    "address",
    "contract",
    "contractAddress",
    "contract_address",
    "targetAddress",
    "target_address",
    "to",
    "account",
    "target",
)

# Payload keys that may hold the chain id.
_CHAIN_ID_KEYS: tuple[str, ...] = (
    "chainId",
    "chain_id",
    "chainid",
    "networkId",
    "network_id",
    "network",
    "chain",
)

# Payload keys that may hold the block number.
_BLOCK_KEYS: tuple[str, ...] = (
    "blockNumber",
    "block_number",
    "block",
    "blockHash",  # last-resort; only used if no numeric block present
)

# Payload keys that may hold the transaction hash.
_TX_HASH_KEYS: tuple[str, ...] = (
    "transactionHash",
    "transaction_hash",
    "txHash",
    "tx_hash",
    "hash",
    "tx",
)


class TriggerError(ValueError):
    """Raised when a webhook payload is structurally unusable (not a mapping, or
    carries no recoverable event name + address)."""


@dataclass(frozen=True)
class DriftEvent:
    """A normalized control-plane event, provider-agnostic.

    ``event`` is the raw (un-normalized) event name as it appeared in the
    payload, so downstream logging/capsules keep the on-chain spelling. Use
    :func:`is_control_plane_event` to classify it. ``address`` is lowercased for
    stable index lookups. ``raw`` retains the original payload for audit.
    """

    event: str
    address: str
    chain_id: int | None = None
    block: int | None = None
    tx_hash: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Normalization helpers
# --------------------------------------------------------------------------- #


def _normalize_name(name: str) -> str:
    """Lowercase and strip non-alphanumerics so name variants collapse.

    "OwnershipTransferred(address,address)" -> "ownershiptransferredaddressaddress"
    "role_granted" -> "rolegranted"; "Admin Changed" -> "adminchanged".
    """

    return "".join(ch for ch in name.lower() if ch.isalnum())


def _normalize_address(value: Any) -> str:
    """Lowercase a hex address; return "" for anything unusable.

    Tolerant of values that arrive with surrounding whitespace or without the
    ``0x`` prefix. Does NOT validate the checksum (we lowercase, never assert a
    specific case) or the length beyond a basic hex sanity check, so unusual but
    legitimate addresses are not silently dropped.
    """

    if not isinstance(value, str):
        return ""
    addr = value.strip().lower()
    if not addr:
        return ""
    if not addr.startswith("0x"):
        addr = "0x" + addr
    body = addr[2:]
    if not body or any(ch not in "0123456789abcdef" for ch in body):
        return ""
    return addr


def _first_present(payload: dict[str, Any], keys: tuple[str, ...]) -> Any:
    """Return the first non-empty value among ``keys`` in ``payload``."""

    for key in keys:
        if key in payload:
            value = payload[key]
            if value is not None and value != "":
                return value
    return None


def _coerce_int(value: Any) -> int | None:
    """Best-effort int coercion handling decimal and 0x-hex strings."""

    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            if text.lower().startswith("0x"):
                return int(text, 16)
            return int(text, 10)
        except ValueError:
            return None
    return None


# Keys that genuinely name the *event* (as opposed to a sentinel/monitor name).
# Used to pull the event identity out of a ``matchReasons`` entry, which is the
# authoritative source of the event for OZ Monitor / Defender payloads.
_EVENT_SIGNATURE_KEYS: tuple[str, ...] = (
    "signature",
    "eventSignature",
    "eventName",
    "event_name",
    "event",
)


def _unwrap_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Flatten the common OZ Monitor / Defender envelope into a flat view.

    OZ-style payloads nest the useful fields under containers like ``match``,
    ``event``, ``trigger``, ``sentinel``, ``transaction``, or a ``matchReasons``
    list. We build a shallow merged view (outer keys take precedence, then known
    nested containers fill gaps) so :func:`parse_monitor_event` can read flat
    keys regardless of which provider shape arrived. The original payload is
    preserved untouched for :attr:`DriftEvent.raw`.

    A nested container's ``name`` is a *monitor/sentinel* name, NOT an event
    name, so ``name`` is deliberately not propagated up from nested containers
    (only an outer top-level ``name`` survives). The authoritative event name is
    extracted separately from ``matchReasons`` by :func:`_extract_event_name`.
    """

    merged: dict[str, Any] = {}

    # Known nested containers, lowest precedence first so outer keys win.
    nested_keys = (
        "sentinel",
        "trigger",
        "transaction",
        "block",
        "event",
        "match",
        "data",
    )
    for key in nested_keys:
        container = payload.get(key)
        if isinstance(container, dict):
            for k, v in container.items():
                if k == "name":
                    # Do not let a sentinel/monitor "name" masquerade as the
                    # event name when it bubbles up to the flat view.
                    continue
                merged[k] = v

    # Outer keys always win over nested (including a real top-level ``name``).
    for k, v in payload.items():
        merged[k] = v

    return merged


def _extract_event_name(payload: dict[str, Any], view: dict[str, Any]) -> str:
    """Resolve the on-chain event name with provider-correct precedence.

    1. ``matchReasons`` (OZ Monitor / Defender): the first reason that carries an
       event signature / name is authoritative -- this is what actually matched.
    2. Otherwise fall back to flat event-name keys in the merged view.
    """

    reasons = payload.get("matchReasons")
    if isinstance(reasons, list):
        for reason in reasons:
            if isinstance(reason, dict):
                value = _first_present(reason, _EVENT_SIGNATURE_KEYS)
                if value:
                    return str(value).strip()

    raw_event = _first_present(view, _EVENT_NAME_KEYS)
    return str(raw_event).strip() if raw_event is not None else ""


_EVENT_ENVELOPE_KEYS: tuple[str, ...] = (
    "sentinel",
    "trigger",
    "transaction",
    "block",
    "match",
    "data",
    "chainId",
    "chain_id",
    "chainid",
    "networkId",
    "network_id",
    "network",
    "chain",
)


def _event_payload_from_envelope(
    payload: dict[str, Any],
    event_payload: dict[str, Any],
) -> dict[str, Any]:
    """Merge one batched event with useful webhook-level envelope fields.

    OpenZeppelin Monitor raw mode and legacy Defender-style webhooks may deliver
    multiple decoded events under ``events`` while transaction / chain metadata
    lives on the outer object. The event object wins so its signature/address are
    authoritative, but the shared envelope remains available for block, tx hash,
    and chain id extraction.
    """

    merged: dict[str, Any] = {}
    for key in _EVENT_ENVELOPE_KEYS:
        if key in payload:
            merged[key] = payload[key]
    merged.update(event_payload)
    return merged


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def parse_monitor_event(payload: dict[str, Any]) -> DriftEvent:
    """Normalize an OZ Monitor / Defender / generic webhook payload.

    Reads the event name, contract address, chain id, block, and tx hash from
    whichever of the well-known keys are present (including one level of the
    common OZ/Defender nesting), and returns a :class:`DriftEvent`.

    Raises :class:`TriggerError` if ``payload`` is not a mapping, or carries
    neither a recoverable event name nor a recoverable address (a payload with
    nothing to act on is a programming/integration error, not a routable event).
    """

    if not isinstance(payload, dict):
        raise TriggerError(f"payload must be a mapping, got {type(payload).__name__}")

    view = _unwrap_payload(payload)

    event = _extract_event_name(payload, view)

    address = _normalize_address(_first_present(view, _ADDRESS_KEYS))

    if not event and not address:
        raise TriggerError(
            "payload carries no recoverable event name or contract address"
        )

    chain_id = _coerce_int(_first_present(view, _CHAIN_ID_KEYS))

    # Block: prefer a numeric block number; fall back to a hash only if no
    # numeric value is present (kept as None since the field is typed int).
    block = _coerce_int(_first_present(view, _BLOCK_KEYS))

    tx_hash_value = _first_present(view, _TX_HASH_KEYS)
    tx_hash = str(tx_hash_value).strip() if tx_hash_value is not None else ""

    return DriftEvent(
        event=event,
        address=address,
        chain_id=chain_id,
        block=block,
        tx_hash=tx_hash,
        raw=dict(payload),
    )


def extract_drift_events(payload: dict[str, Any]) -> tuple[DriftEvent, ...]:
    """Normalize one webhook body into one or more :class:`DriftEvent`s.

    ``parse_monitor_event`` handles a single event payload. This helper handles
    webhook bodies that batch decoded events under an ``events`` array (the
    common OZ Monitor raw / Defender monitor shape) by merging each child event
    with the transaction and chain metadata from the outer envelope.
    """

    if not isinstance(payload, dict):
        raise TriggerError(f"payload must be a mapping, got {type(payload).__name__}")

    events = payload.get("events")
    if isinstance(events, list):
        parsed: list[DriftEvent] = []
        last_error: TriggerError | None = None
        for item in events:
            if not isinstance(item, dict):
                continue
            try:
                parsed.append(parse_monitor_event(_event_payload_from_envelope(payload, item)))
            except TriggerError as exc:
                last_error = exc
        if parsed:
            return tuple(parsed)
        if last_error is not None:
            raise TriggerError(f"events array contains no recoverable drift events: {last_error}")
        raise TriggerError("events array contains no event objects")

    return (parse_monitor_event(payload),)


def is_control_plane_event(event_name: str) -> bool:
    """True if ``event_name`` is a control-plane event worth a scan.

    Control-plane events change *who controls* the protocol or *what code runs*:
    ownership, access-control roles, proxy admin, implementation upgrades, Safe
    threshold / signer / module policy, timelock delay, guardian / pauser. A
    transfer, swap, deposit, or other data-plane event returns ``False`` so the
    trigger does not burn a scan on it.

    Matching is normalization + substring based, so name variants and full event
    signatures ("OwnershipTransferred(address,address)") are caught.
    """

    if not event_name or not isinstance(event_name, str):
        return False
    normalized = _normalize_name(event_name)
    if not normalized:
        return False
    return any(marker in normalized for marker in CONTROL_PLANE_MARKERS)


def build_collector_invocation(
    event: DriftEvent,
    targets_index: dict[str, Any],
) -> dict[str, Any]:
    """Map an event's address back to a target and produce the scan invocation.

    ``targets_index`` maps a *lowercased contract address* to a target
    descriptor. The descriptor is opaque to this module but, in practice, is a
    :class:`~protocolgate.factory.FactoryTarget` (or a dict with at least
    ``name`` + ``manifest``); :func:`build_targets_index` builds exactly this
    shape from a loaded ``targets.yaml`` + its manifests.

    Returns a plain, JSON-serializable invocation describing the next pass:

        {
          "invoke": bool,            # False => degrade to no-op (see below)
          "reason": str,             # why we did / did not enqueue
          "event": str,             # raw event name
          "address": str,           # lowercased trigger address
          "chain_id": int | None,
          "block": int | None,
          "tx_hash": str,
          "target": <descriptor> | None,  # resolved target, if any
          "target_name": str,        # convenience, "" when unresolved
          "pipeline": ["collect_snapshot", "compare_snapshot", "factory_enqueue"],
        }

    Degradation rules (never raise on routable-but-unactionable input):

    - Unknown address  -> ``invoke=False``, ``reason="unknown-address"``. A
      webhook for an address we do not own is normal noise, not an error.
    - Non-control-plane event on a known address -> ``invoke=False``,
      ``reason="not-control-plane"``. We own the address but this event does not
      justify paying for a scan.
    - Empty/missing address -> ``invoke=False``, ``reason="no-address"``.

    Only when the address resolves AND the event is control-plane do we return
    ``invoke=True`` with ``reason="control-plane-drift"``.
    """

    address = _normalize_address(event.address)
    base: dict[str, Any] = {
        "invoke": False,
        "reason": "",
        "event": event.event,
        "address": address,
        "chain_id": event.chain_id,
        "block": event.block,
        "tx_hash": event.tx_hash,
        "target": None,
        "target_name": "",
        "pipeline": ["collect_snapshot", "compare_snapshot", "factory_enqueue"],
    }

    if not address:
        base["reason"] = "no-address"
        return base

    index = targets_index or {}
    target = index.get(address)
    if target is None:
        # Tolerate an index keyed by mixed-case addresses by falling back to a
        # case-insensitive scan (cheap; the index is small).
        for key, value in index.items():
            if isinstance(key, str) and key.lower() == address:
                target = value
                break

    if target is None:
        base["reason"] = "unknown-address"
        return base

    base["target"] = target
    base["target_name"] = _target_name(target)

    if not is_control_plane_event(event.event):
        base["reason"] = "not-control-plane"
        return base

    base["invoke"] = True
    base["reason"] = "control-plane-drift"
    return base


def build_targets_index(
    targets: list[Any],
    manifests: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build an address -> target index from factory targets + their manifests.

    ``targets`` is a list of target descriptors (FactoryTarget instances or
    dicts) each exposing a ``manifest`` path and a ``name``. ``manifests`` maps a
    manifest path to its loaded/normalized manifest dict. Every contract,
    multisig, and timelock address declared in a target's manifest is mapped to
    that target, so an event on any of those addresses routes back to the right
    scan.

    This is the only place ``targets.yaml`` (which holds manifest *paths*, not
    addresses) is joined to manifests (which hold the addresses). It is a
    convenience for callers; :func:`build_collector_invocation` accepts any
    pre-built index, so tests can pass a hand-rolled dict.
    """

    index: dict[str, Any] = {}
    for target in targets:
        manifest_path = _target_attr(target, "manifest")
        if not manifest_path:
            continue
        manifest = manifests.get(str(manifest_path))
        if not isinstance(manifest, dict):
            continue
        for section in ("contracts", "multisigs", "timelocks"):
            for entry in manifest.get(section, []) or []:
                if not isinstance(entry, dict):
                    continue
                addr = _normalize_address(entry.get("address"))
                if addr:
                    # First target to claim an address wins; addresses are
                    # globally unique on a chain, so collisions indicate a
                    # mis-configured targets file and we keep the first mapping
                    # deterministically.
                    index.setdefault(addr, target)
    return index


# --------------------------------------------------------------------------- #
# Small accessors that work for both dataclasses and dicts
# --------------------------------------------------------------------------- #


def _target_attr(target: Any, attr: str) -> Any:
    if isinstance(target, dict):
        return target.get(attr)
    return getattr(target, attr, None)


def _target_name(target: Any) -> str:
    name = _target_attr(target, "name")
    return str(name) if name else ""
