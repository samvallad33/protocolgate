"""Event-driven webhook receiver for the bounty factory.

ProtocolGate's batch entry point is ``protocolgate factory targets.yaml``, which
walks every target on demand. This module adds the *event-driven* half of the
loop: a monitor (a block explorer alert, a Tenderly/OZ Defender webhook, a Safe
transaction-service hook, etc.) POSTs a drift event, and we run the
collect -> reason -> drift -> classify factory loop through the existing factory
hook, then return the mapped target's outcome.

Why this earns its keep (north-star economics): a webhook only fires when a
control-plane surface actually moved on-chain, so the router spends a scan
exactly when a scan can pay -- instead of re-walking every target on a timer.
Non-control-plane noise is acknowledged and dropped without spending a scan,
which is itself a tracked "scan skipped" (a dead-door avoided cheaply).

Design constraints (load-bearing, do not violate):

- BRIGHT LINE preserved end to end. This receiver only invokes
  :func:`protocolgate.factory.run_factory`, which never auto-promotes to
  ``submission-ready``. The webhook is read-only and fork-only downstream; it
  never submits and never signs.
- Dependency-free. Standard-library ``http.server`` only -- no Flask, FastAPI,
  aiohttp, or any new framework. Keeps the install surface tiny and the bright
  line auditable.
- Injectable I/O for tests. The HTTP layer is a thin shell over the pure
  function :func:`handle_drift_event`, which turns the JSON body into
  :class:`protocolgate.trigger.DriftEvent` values and accepts an injectable
  ``factory_fn``. Tests build a fake request dict and assert routing without
  opening a socket or touching the network.
- Degrade gracefully. A malformed body is a 400, an unmapped/non-control-plane
  event is a benign 202 (acknowledged, no scan), an unknown path is a 404, and
  a factory failure is a 500 with a compact JSON error -- the server never
  crashes the listener on one bad request.
- Style parity with the repo: ``from __future__`` annotations, frozen
  dataclasses, stdlib-first, no network in the importable surface.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from collections.abc import Mapping
from typing import Any, Callable

from protocolgate.factory import FactoryError, TargetResult, run_factory
from protocolgate.trigger import (
    DriftEvent,
    TriggerError,
    extract_drift_events,
    is_control_plane_event,
    parse_monitor_event,
)

_LOG = logging.getLogger("protocolgate.webhook")

# The path the monitor POSTs drift events to. A monitor that cannot be told a
# path can POST to ``/`` as well (handled identically); everything else 404s.
DRIFT_PATHS = ("/drift", "/")

# Env var holding the shared HMAC secret. When SET, every drift POST must carry
# a valid ``X-ProtocolGate-Signature`` header or it is rejected 401 before any
# JSON parse or factory work runs. When UNSET, the receiver stays open (current
# behavior) but logs a warning so the unauthenticated state is opt-in, visible,
# and never the silent default in prod.
WEBHOOK_SECRET_ENV = "PROTOCOLGATE_WEBHOOK_SECRET"
# Header the monitor signs the raw body with: ``sha256=<hexdigest>`` of
# HMAC-SHA256(secret, raw_body).
SIGNATURE_HEADER = "X-ProtocolGate-Signature"
_SIGNATURE_PREFIX = "sha256="


def _compute_signature(secret: str, body: bytes) -> str:
    """Return the ``sha256=<hexdigest>`` HMAC-SHA256 signature for ``body``."""

    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"{_SIGNATURE_PREFIX}{digest}"


def _is_authorized(secret: str, body: bytes, signature_header: str | None) -> bool:
    """Constant-time check that ``signature_header`` matches ``body`` under ``secret``.

    A missing or malformed header is unauthorized. The comparison is over the
    full ``sha256=<hexdigest>`` form using :func:`hmac.compare_digest` so neither
    the digest nor the prefix leaks via timing.

    ``hmac.compare_digest`` raises ``TypeError`` when a ``str`` operand contains
    non-ASCII characters, so a non-ASCII signature header would otherwise crash
    the authenticated path (DoS). A valid signature is always ASCII hex, so we
    reject any non-ASCII header as unauthorized rather than letting it raise.
    """

    if not signature_header:
        return False
    candidate = signature_header.strip()
    if not candidate.isascii():
        return False
    expected = _compute_signature(secret, body)
    return hmac.compare_digest(expected, candidate)

# An injectable factory runner matching :func:`protocolgate.factory.run_factory`'s
# shape so tests inject a fake that returns a canned ``FactoryResult`` with no
# collector, RPC, or Vestige network.
FactoryFn = Callable[..., Any]
# A request handler the server delegates to. Defaults to one bound to a
# ``targets.yaml`` + factory runner; tests inject their own to assert routing.
DriftHandler = Callable[["WebhookRequest"], "WebhookResponse"]


@dataclass(frozen=True)
class WebhookRequest:
    """A minimal, transport-agnostic view of one inbound request.

    The real HTTP handler builds this from the socket; tests build it by hand.
    Keeping the pure logic on this struct is what lets the whole receiver be
    tested with zero network.
    """

    method: str
    path: str
    body: bytes = b""
    # Case-insensitive view of inbound HTTP headers. The real handler fills this
    # from the socket; tests build it by hand. Only used for the optional HMAC
    # auth check, which runs on the raw ``body`` before any JSON parse.
    headers: Mapping[str, str] | None = None

    def header(self, name: str) -> str | None:
        """Case-insensitive single-header lookup. ``None`` when absent."""

        if not self.headers:
            return None
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None


@dataclass(frozen=True)
class WebhookResponse:
    """A minimal HTTP response the transport shell serializes."""

    status: int
    payload: dict[str, Any]

    def to_bytes(self) -> bytes:
        return json.dumps(self.payload, default=str).encode("utf-8")


WebhookError = TriggerError


def map_event_to_target(event: DriftEvent, result: Any) -> TargetResult | None:
    """Pick the factory ``TargetResult`` this event refers to, or ``None``.

    Matching precedence (each case-insensitive, whitespace-trimmed):

    1. exact target name,
    2. address present in the target's collected snapshot (contract/multisig),
    3. a single-target run (the unambiguous case) when the event carries no
       usable selector.

    Returning ``None`` means the event did not map to any known target: the
    caller acks it without claiming a finding.
    """

    results: tuple[TargetResult, ...] = tuple(getattr(result, "results", ()) or ())
    if not results:
        return None

    wanted_name = _event_target_name(event).strip().lower()
    if wanted_name:
        for tr in results:
            if tr.name.strip().lower() == wanted_name:
                return tr

    wanted_addr = event.address.strip().lower()
    if wanted_addr:
        for tr in results:
            if _snapshot_has_address(tr.snapshot, wanted_addr):
                return tr

    if not wanted_name and not wanted_addr and len(results) == 1:
        return results[0]

    return None


def _event_target_name(event: DriftEvent) -> str:
    for key in ("target", "target_name", "targetName", "protocol", "project", "label"):
        value = event.raw.get(key)
        if value is not None and value != "":
            return str(value)
    return ""


def _snapshot_has_address(snapshot: dict[str, Any], wanted: str) -> bool:
    for bucket in ("contracts", "multisigs"):
        for obj in snapshot.get(bucket, []) or []:
            addr = str(obj.get("address", "")).strip().lower()
            if addr and addr == wanted:
                return True
    return False


def _target_result_summary(tr: TargetResult) -> dict[str, Any]:
    """Compact, audit-friendly view of one target's factory outcome."""

    return {
        "name": tr.name,
        "chain": tr.chain,
        "state": tr.state,
        "block": tr.block,
        "vestige_available": tr.vestige_available,
        "economics": tr.economics.to_dict(),
        "lanes": [
            {
                "subject": lane.subject,
                "kind": lane.kind,
                "status": lane.status,
                "skipped_dead_door": lane.skipped_dead_door,
                "reasoning_action": lane.reasoning_action,
                "reasoning_refs": list(lane.reasoning_refs),
                "budget_action": (
                    lane.budget_decision.action
                    if lane.budget_decision is not None
                    else ""
                ),
                "poc_status": lane.poc_status,
                "poc_proven": lane.poc_proven,
                "poc_usd_impact": lane.poc_usd_impact,
            }
            for lane in tr.lanes
        ],
        "errors": list(tr.errors),
    }


def _event_summary(event: DriftEvent) -> dict[str, Any]:
    return {
        "event": event.event,
        "address": event.address,
        "chain_id": event.chain_id,
        "block": event.block,
        "tx_hash": event.tx_hash,
        "target": _event_target_name(event),
        "control_plane": is_control_plane_event(event.event),
    }


def handle_drift_event(
    request: WebhookRequest,
    *,
    targets_path: str | Path,
    factory_fn: FactoryFn = run_factory,
    **factory_kwargs: Any,
) -> WebhookResponse:
    """Route one request to the factory loop. Pure: no socket, no network here.

    Behavior:

    - non-POST -> 405,
    - path not in :data:`DRIFT_PATHS` -> 404,
    - unparseable JSON or non-control-plane / unmappable event -> 202 ack with a
      ``"scanned": false`` body (a cheap "scan skipped"); a *control-plane*
      event still runs the factory,
    - control-plane event -> run ``factory_fn(targets_path, ...)``, select the
      mapped target, and return its classification (200),
    - factory failure -> 500 with a compact error.

    The factory it calls (``run_factory``) never auto-promotes to
    submission-ready, so this endpoint inherits the bright line by construction.
    """

    if request.method.upper() != "POST":
        return WebhookResponse(405, {"error": "method not allowed", "method": request.method})

    if request.path not in DRIFT_PATHS:
        return WebhookResponse(404, {"error": "not found", "path": request.path})

    # HMAC gate (opt-in). When the shared secret is configured, every drift POST
    # must carry a valid signature over the RAW body before we parse JSON or
    # spend a scan -- this closes the unauthenticated DoS amplifier (RPC fan-out
    # + subprocess spawns on any anonymous POST). When unset we stay open for
    # local dev but warn loudly so the unauthenticated state is never silent.
    secret = os.environ.get(WEBHOOK_SECRET_ENV)
    if secret:
        if not _is_authorized(secret, request.body, request.header(SIGNATURE_HEADER)):
            return WebhookResponse(401, {"error": "invalid or missing signature"})
    else:
        _LOG.warning(
            "%s is not set: the drift webhook is UNAUTHENTICATED. Any POST to %s "
            "can trigger a factory scan. Set %s to require %s HMAC-SHA256 auth.",
            WEBHOOK_SECRET_ENV,
            " or ".join(DRIFT_PATHS),
            WEBHOOK_SECRET_ENV,
            SIGNATURE_HEADER,
        )

    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return WebhookResponse(400, {"error": "invalid JSON body", "detail": str(exc)})

    try:
        events = extract_drift_events(payload)
    except TriggerError as exc:
        return WebhookResponse(400, {"error": "invalid event", "detail": str(exc)})

    control_events = tuple(event for event in events if is_control_plane_event(event.event))
    if not control_events:
        # Monitor noise: acknowledge, spend no scan. This is the cheap-skip the
        # economics layer counts as a dead-door avoided.
        return WebhookResponse(
            202,
            {
                "acknowledged": True,
                "scanned": False,
                "reason": "non-control-plane event ignored",
                "event_count": len(events),
                "events": [_event_summary(event) for event in events],
            },
        )

    try:
        result = factory_fn(targets_path, **factory_kwargs)
    except FactoryError as exc:
        return WebhookResponse(400, {"error": "targets error", "detail": str(exc)})
    except Exception as exc:  # noqa: BLE001 - one bad event must not kill the listener
        return WebhookResponse(500, {"error": "factory failure", "detail": str(exc)})

    mapped: list[dict[str, Any]] = []
    unmapped: list[dict[str, Any]] = []
    for event in control_events:
        target = map_event_to_target(event, result)
        if target is None:
            unmapped.append(_event_summary(event))
            continue
        mapped.append(
            {
                "event": _event_summary(event),
                "target": target.name,
                "state": target.state,
                "result": _target_result_summary(target),
            }
        )

    if not mapped:
        return WebhookResponse(
            202,
            {
                "acknowledged": True,
                "scanned": False,
                "factory_invoked": True,
                "reason": "control-plane event did not map to a known target",
                "event_count": len(events),
                "control_plane_event_count": len(control_events),
                "unmapped_events": unmapped,
            },
        )

    payload_out: dict[str, Any] = {
        "acknowledged": True,
        "scanned": True,
        "event_count": len(events),
        "control_plane_event_count": len(control_events),
        "results": mapped,
    }
    if unmapped:
        payload_out["unmapped_events"] = unmapped
    if len(mapped) == 1:
        only = mapped[0]
        payload_out.update(
            {
                "event_type": only["event"]["event"],
                "target": only["target"],
                "state": only["state"],
                "result": only["result"],
            }
        )
    return WebhookResponse(200, payload_out)


def make_default_handler(
    targets_path: str | Path,
    *,
    factory_fn: FactoryFn = run_factory,
    **factory_kwargs: Any,
) -> DriftHandler:
    """Bind ``targets_path`` + factory runner into a single-arg drift handler."""

    def _handler(request: WebhookRequest) -> WebhookResponse:
        return handle_drift_event(
            request,
            targets_path=targets_path,
            factory_fn=factory_fn,
            **factory_kwargs,
        )

    return _handler


def _build_request_handler(handler: DriftHandler) -> type[BaseHTTPRequestHandler]:
    """Create a ``BaseHTTPRequestHandler`` subclass bound to ``handler``."""

    class _DriftRequestHandler(BaseHTTPRequestHandler):
        # Quiet by default: the monitor, not a human, is the client. Override
        # log_message so a high-volume monitor does not spam stderr.
        def log_message(self, *_args: Any) -> None:  # noqa: D401, ANN401
            return

        def _respond(self, response: WebhookResponse) -> None:
            body = response.to_bytes()
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> bytes:
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                length = 0
            if length <= 0:
                return b""
            return self.rfile.read(length)

        def do_POST(self) -> None:  # noqa: N802 - http.server naming
            request = WebhookRequest(
                method="POST",
                path=self.path,
                body=self._read_body(),
                headers={k: v for k, v in self.headers.items()},
            )
            self._respond(handler(request))

        def do_GET(self) -> None:  # noqa: N802 - http.server naming
            # A bare GET is treated as a liveness probe on the drift path only.
            if self.path in DRIFT_PATHS:
                self._respond(WebhookResponse(200, {"status": "ok", "ready": True}))
            else:
                self._respond(WebhookResponse(404, {"error": "not found", "path": self.path}))

    return _DriftRequestHandler


def run_webhook_server(
    targets_path: str | Path,
    host: str = "127.0.0.1",
    port: int = 8787,
    *,
    handler: DriftHandler | None = None,
    factory_fn: FactoryFn = run_factory,
    serve: bool = True,
    **factory_kwargs: Any,
) -> ThreadingHTTPServer:
    """Start the stdlib webhook receiver for the event-driven factory loop.

    Binds ``host:port`` and POSTs to :data:`DRIFT_PATHS` run the factory loop
    for the mapped target. ``handler`` is injectable so tests can drive routing
    without a network round-trip; when omitted, a default handler bound to
    ``targets_path`` + ``factory_fn`` is used.

    With ``serve=True`` (default) this blocks serving forever (Ctrl-C to stop).
    With ``serve=False`` it returns the bound, not-yet-serving server so a caller
    or test can drive ``handle_request`` / ``serve_forever`` itself. Returns the
    server in both cases (it is already closed after a blocking ``serve``).
    """

    drift_handler = handler or make_default_handler(
        targets_path, factory_fn=factory_fn, **factory_kwargs
    )
    request_handler = _build_request_handler(drift_handler)
    httpd = ThreadingHTTPServer((host, port), request_handler)
    if not serve:
        return httpd
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
    return httpd
