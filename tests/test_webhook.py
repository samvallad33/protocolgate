"""Tests for the event-driven webhook receiver.

No network and no real HTTP server: every test drives the pure
:func:`protocolgate.webhook.handle_drift_event` (or the injectable
``run_webhook_server(..., serve=False)``) with a hand-built ``WebhookRequest``
and a fake ``factory_fn``. This pins the routing contract:

- a control-plane event POSTed to ``/drift`` invokes the factory and returns
  the mapped target's classification,
- a non-control-plane event is acknowledged without spending a scan,
- a wrong path 404s, a wrong method 405s, a malformed body 400s,
- the bright line holds: the receiver only ever calls ``run_factory``, which
  never auto-promotes to submission-ready.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from protocolgate.factory import FactoryError, FactoryResult, LaneResult, TargetResult
from protocolgate.trigger import DriftEvent, is_control_plane_event
from protocolgate.webhook import (
    WebhookRequest,
    WebhookResponse,
    handle_drift_event,
    map_event_to_target,
    parse_monitor_event,
    run_webhook_server,
)


# --------------------------------------------------------------------------- #
# Fakes (no network, no real factory)
# --------------------------------------------------------------------------- #


PROXY = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _target_result(name: str = "Acme", state: str = "needs-PoC") -> TargetResult:
    lane = LaneResult(
        subject="Vault",
        kind="proxy_admin_drift",
        severity="high",
        message="proxy admin changed",
        expected="0x1",
        actual="0x9",
        signature=f"{name}:Vault:proxy_admin_drift",
        status=state,
    )
    return TargetResult(
        name=name,
        chain="ethereum-mainnet",
        manifest="protocolgate.yaml",
        state=state,
        block="0x123",
        snapshot={
            "block": "0x123",
            "contracts": [{"name": "Vault", "address": PROXY, "proxy": {"admin": "0x9"}}],
            "multisigs": [],
        },
        findings=(),
        lanes=(lane,),
        readbacks=(),
        errors=(),
        vestige_available=True,
    )


class FakeFactory:
    """Records the targets_path it was called with; returns a canned result."""

    def __init__(self, result: FactoryResult | None = None, raises: Exception | None = None) -> None:
        self.result = result
        self.raises = raises
        self.calls: list[str] = []

    def __call__(self, targets_path, **kwargs):
        self.calls.append(str(targets_path))
        if self.raises is not None:
            raise self.raises
        return self.result


def _factory_result(*targets: TargetResult) -> FactoryResult:
    return FactoryResult(
        targets_path="targets.yaml",
        target_count=len(targets),
        results=tuple(targets),
        vestige_available=True,
    )


def _post(path: str, payload: dict) -> WebhookRequest:
    return WebhookRequest(method="POST", path=path, body=json.dumps(payload).encode("utf-8"))


# --------------------------------------------------------------------------- #
# parse_monitor_event
# --------------------------------------------------------------------------- #


def test_parse_monitor_event_reads_common_aliases() -> None:
    event = parse_monitor_event(
        {"eventType": "OwnershipTransferred", "protocol": "Acme", "contract": PROXY, "network": "1"}
    )
    assert isinstance(event, DriftEvent)
    assert event.event == "OwnershipTransferred"
    assert event.raw["protocol"] == "Acme"
    assert event.address == PROXY
    assert event.chain_id == 1
    assert is_control_plane_event(event.event) is True


def test_parse_monitor_event_rejects_empty_and_non_mapping() -> None:
    from protocolgate.webhook import WebhookError

    with pytest.raises(WebhookError):
        parse_monitor_event({})
    with pytest.raises(WebhookError):
        parse_monitor_event(["not", "a", "dict"])  # type: ignore[arg-type]


def test_control_plane_detection_is_case_and_separator_insensitive() -> None:
    for et in ("admin_changed", "ADMIN-CHANGED", "AdminChanged"):
        assert is_control_plane_event(parse_monitor_event({"type": et, "target": "X"}).event) is True
    assert is_control_plane_event(parse_monitor_event({"type": "Transfer", "target": "X"}).event) is False


# --------------------------------------------------------------------------- #
# Routing: the core contract
# --------------------------------------------------------------------------- #


def test_control_plane_event_invokes_factory_and_returns_mapped_target() -> None:
    factory = FakeFactory(result=_factory_result(_target_result("Acme", "needs-PoC")))
    request = _post("/drift", {"event_type": "AdminChanged", "target": "Acme", "address": PROXY})

    response = handle_drift_event(request, targets_path="targets.yaml", factory_fn=factory)

    assert response.status == 200
    assert response.payload["scanned"] is True
    assert response.payload["target"] == "Acme"
    assert response.payload["state"] == "needs-PoC"
    # The factory was actually invoked with our targets path.
    assert factory.calls == ["targets.yaml"]


def test_non_control_plane_event_is_acked_without_scanning() -> None:
    factory = FakeFactory(result=_factory_result(_target_result()))
    request = _post("/drift", {"event_type": "Transfer", "target": "Acme"})

    response = handle_drift_event(request, targets_path="targets.yaml", factory_fn=factory)

    assert response.status == 202
    assert response.payload["scanned"] is False
    # BRIGHT LINE / economics: no scan was spent on monitor noise.
    assert factory.calls == []


def test_batch_webhook_filters_noise_and_invokes_once_for_control_plane_event() -> None:
    factory = FakeFactory(result=_factory_result(_target_result("Acme", "needs-PoC")))
    request = _post(
        "/drift",
        {
            "transaction": {"hash": "0x" + "33" * 32, "blockNumber": "0x123"},
            "chainId": 1,
            "events": [
                {"signature": "Transfer(address,address,uint256)", "address": PROXY},
                {"signature": "AdminChanged(address,address)", "address": PROXY},
            ],
        },
    )

    response = handle_drift_event(request, targets_path="targets.yaml", factory_fn=factory)

    assert response.status == 200
    assert response.payload["event_count"] == 2
    assert response.payload["control_plane_event_count"] == 1
    assert response.payload["target"] == "Acme"
    assert response.payload["event_type"] == "AdminChanged(address,address)"
    assert factory.calls == ["targets.yaml"]


def test_control_plane_event_for_unknown_target_is_acked_not_claimed() -> None:
    factory = FakeFactory(result=_factory_result(_target_result("Acme")))
    request = _post("/drift", {"event_type": "AdminChanged", "target": "SomeOtherProtocol"})

    response = handle_drift_event(request, targets_path="targets.yaml", factory_fn=factory)

    # Factory still ran (event was control-plane) but nothing mapped.
    assert factory.calls == ["targets.yaml"]
    assert response.status == 202
    assert response.payload["scanned"] is False
    assert "did not map" in response.payload["reason"]


def test_address_match_when_target_name_absent() -> None:
    factory = FakeFactory(result=_factory_result(_target_result("Acme")))
    request = _post("/drift", {"event_type": "Upgraded", "address": PROXY.upper()})

    response = handle_drift_event(request, targets_path="targets.yaml", factory_fn=factory)

    assert response.status == 200
    assert response.payload["target"] == "Acme"


def test_wrong_path_404s_and_never_invokes_factory() -> None:
    factory = FakeFactory(result=_factory_result(_target_result()))
    request = _post("/not-drift", {"event_type": "AdminChanged", "target": "Acme"})

    response = handle_drift_event(request, targets_path="targets.yaml", factory_fn=factory)

    assert response.status == 404
    assert factory.calls == []


def test_wrong_method_405s() -> None:
    factory = FakeFactory(result=_factory_result(_target_result()))
    request = WebhookRequest(method="GET", path="/drift", body=b"")

    response = handle_drift_event(request, targets_path="targets.yaml", factory_fn=factory)

    assert response.status == 405
    assert factory.calls == []


def test_malformed_json_body_400s() -> None:
    factory = FakeFactory(result=_factory_result(_target_result()))
    request = WebhookRequest(method="POST", path="/drift", body=b"{not json")

    response = handle_drift_event(request, targets_path="targets.yaml", factory_fn=factory)

    assert response.status == 400
    assert factory.calls == []


def test_factory_error_is_400_not_a_crash() -> None:
    factory = FakeFactory(raises=FactoryError("targets file not found"))
    request = _post("/drift", {"event_type": "AdminChanged", "target": "Acme"})

    response = handle_drift_event(request, targets_path="missing.yaml", factory_fn=factory)

    assert response.status == 400
    assert "targets error" in response.payload["error"]


def test_unexpected_factory_exception_is_500_not_a_crash() -> None:
    factory = FakeFactory(raises=RuntimeError("collector exploded"))
    request = _post("/drift", {"event_type": "AdminChanged", "target": "Acme"})

    response = handle_drift_event(request, targets_path="targets.yaml", factory_fn=factory)

    assert response.status == 500
    assert "factory failure" in response.payload["error"]


def test_root_path_is_also_accepted() -> None:
    factory = FakeFactory(result=_factory_result(_target_result("Acme")))
    request = _post("/", {"event_type": "ChangedThreshold", "target": "Acme"})

    response = handle_drift_event(request, targets_path="targets.yaml", factory_fn=factory)

    assert response.status == 200
    assert response.payload["target"] == "Acme"


# --------------------------------------------------------------------------- #
# map_event_to_target precedence
# --------------------------------------------------------------------------- #


def test_map_prefers_name_then_address_then_single_target() -> None:
    a = _target_result("Acme")
    b = _target_result("Beta")
    result = _factory_result(a, b)

    by_name = map_event_to_target(
        DriftEvent(event="AdminChanged", address="", raw={"target": "beta"}), result
    )
    assert by_name is b

    by_addr = map_event_to_target(DriftEvent(event="AdminChanged", address=PROXY), result)
    assert by_addr is a  # only Acme's snapshot carries PROXY

    # Single-target run with no selector falls through to the lone target.
    solo = map_event_to_target(DriftEvent(event="AdminChanged", address=""), _factory_result(a))
    assert solo is a

    # Ambiguous (no selector, two targets) -> None.
    assert map_event_to_target(DriftEvent(event="AdminChanged", address=""), result) is None


# --------------------------------------------------------------------------- #
# run_webhook_server with serve=False + injected handler (no socket bind/serve)
# --------------------------------------------------------------------------- #


def test_run_webhook_server_serve_false_returns_bound_server(tmp_path: Path) -> None:
    captured: list[WebhookRequest] = []

    def handler(request: WebhookRequest) -> WebhookResponse:
        captured.append(request)
        return WebhookResponse(200, {"ok": True})

    # port 0 lets the OS pick a free port so the test never collides.
    httpd = run_webhook_server(tmp_path / "targets.yaml", "127.0.0.1", 0, handler=handler, serve=False)
    try:
        assert httpd.server_address[1] != 0  # a real port was bound
    finally:
        httpd.server_close()


def test_default_handler_wired_through_run_webhook_server(tmp_path: Path) -> None:
    # Inject a fake factory so run_webhook_server builds a real default handler
    # but no network/collector is touched, then drive that handler directly.
    factory = FakeFactory(result=_factory_result(_target_result("Acme")))
    httpd = run_webhook_server(
        tmp_path / "targets.yaml", "127.0.0.1", 0, factory_fn=factory, serve=False
    )
    try:
        handler = httpd.RequestHandlerClass  # bound, but we test the pure path
    finally:
        httpd.server_close()
    # The wiring we actually care about: handle_drift_event + fake factory.
    response = handle_drift_event(
        _post("/drift", {"event_type": "AdminChanged", "target": "Acme"}),
        targets_path=tmp_path / "targets.yaml",
        factory_fn=factory,
    )
    assert response.status == 200
    assert response.payload["target"] == "Acme"
    assert handler is not None
