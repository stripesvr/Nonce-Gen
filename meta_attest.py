from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

import aiohttp

GRAPH_VERIFY = "https://graph.oculus.com/platform_integrity/verify"

TOKEN_VALIDITY_SECONDS = 86400
DEVICE_TRUST_ORDER = {"Advanced": 2, "Basic": 1, "NotTrusted": 0}


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("claim payload is empty")
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def normalize_access_token(raw: str) -> str:
    """Dashboard shows OC|APP_ID|APP_SECRET but docs also print OC/APP_ID/APP_SECRET."""
    parts = raw.strip().replace("/", "|").split("|")
    if len(parts) != 3 or not all(parts):
        raise ValueError("META_APP_ACCESS_TOKEN must be OC|APP_ID|APP_SECRET")
    return "|".join(parts)


@dataclass
class Policy:
    expected_nonce: str
    expected_package: str
    allowed_certs: set[str] = field(default_factory=set)
    max_token_age_seconds: int = 300
    clock_skew_seconds: int = 60
    min_device_integrity: str = "Basic"
    require_store_recognized: bool = True


@dataclass
class Result:
    verified: bool
    message: str
    claims: dict | None = None
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def claims_json(self) -> str | None:
        return json.dumps(self.claims, sort_keys=True) if self.claims else None


def evaluate_claims(claims: dict, policy: Policy, now: int | None = None) -> Result:
    now = int(time.time()) if now is None else now
    failures: list[str] = []
    warnings: list[str] = []

    req = claims.get("request_details") or {}
    app = claims.get("app_state") or {}
    dev = claims.get("device_state") or {}

    exp = int(req.get("exp") or 0)
    if exp <= now:
        failures.append("token expired")
    if exp - now > TOKEN_VALIDITY_SECONDS + policy.clock_skew_seconds:
        failures.append("exp beyond 24h ceiling")

    ts = int(req.get("timestamp") or 0)
    age = now - ts
    if age > policy.max_token_age_seconds:
        failures.append(f"timestamp {age}s old (max {policy.max_token_age_seconds}s)")
    if age < -policy.clock_skew_seconds:
        failures.append("timestamp in the future")

    if req.get("nonce") != policy.expected_nonce:
        failures.append("nonce mismatch")

    if app.get("package_id") != policy.expected_package:
        failures.append(f"package_id {app.get('package_id')!r} != {policy.expected_package!r}")

    state = app.get("app_integrity_state")
    if policy.require_store_recognized and state != "StoreRecognized":
        failures.append(f"app_integrity_state {state!r}")

    digests = {str(d).lower() for d in (app.get("package_cert_sha256_digest") or [])}
    if policy.allowed_certs and not (policy.allowed_certs & digests):
        failures.append("cert digest not in pinned set")

    trust = dev.get("device_integrity_state")
    if DEVICE_TRUST_ORDER.get(trust, -1) < DEVICE_TRUST_ORDER.get(policy.min_device_integrity, 1):
        failures.append(f"device_integrity_state {trust!r}")
    elif trust == "Basic":
        warnings.append("device integrity Basic - bootloader locked, system check failed")

    pending = dev.get("security_update_pending_days")
    if isinstance(pending, int) and pending > 90:
        warnings.append(f"security patch pending {pending}d")

    ban = claims.get("device_ban") or {}
    if ban.get("is_banned"):
        warnings.append(f"device_ban active, {ban.get('remaining_ban_time')} min left")

    if not dev.get("unique_id"):
        warnings.append("no unique_id in claims")

    return Result(
        verified=not failures,
        message="verified" if not failures else "; ".join(failures),
        claims=claims,
        failures=failures,
        warnings=warnings,
    )


def interpret_response(body: dict | None, status: int, policy: Policy) -> Result:
    if status >= 400:
        err = (body or {}).get("error") or {}
        return Result(False, err.get("message") or f"graph HTTP {status}")

    data = (body or {}).get("data") or []
    if not data:
        return Result(False, "empty graph response")

    first = data[0]
    message = str(first.get("message", ""))
    if message != "success":
        return Result(False, message or "verification rejected")

    blob = first.get("claims")
    if not blob:
        return Result(False, "success without claims")

    try:
        claims = json.loads(b64url_decode(blob))
    except (ValueError, json.JSONDecodeError) as exc:
        return Result(False, f"claims decode failed: {exc}")

    if not isinstance(claims, dict):
        return Result(False, "claims are not an object")

    return evaluate_claims(claims, policy)


class AttestationClient:
    """Async transport. Used by the bot."""

    def __init__(self, session: aiohttp.ClientSession, access_token: str, *, graph_url: str = GRAPH_VERIFY) -> None:
        self._session = session
        self._token = normalize_access_token(access_token)
        self._graph_url = graph_url

    async def verify(self, attestation_token: str, policy: Policy) -> Result:
        body, status = await self._graph_call(
            {"token": attestation_token.strip(), "access_token": self._token}
        )
        return interpret_response(body, status, policy)

    async def _graph_call(self, payload: dict) -> tuple[dict | None, int]:
        timeout = aiohttp.ClientTimeout(total=20)
        async with self._session.post(self._graph_url, data=payload, timeout=timeout) as resp:
            text = await resp.text()
            status = resp.status

        # Some graph edges only honor query params. Retry once on 404/405.
        if status in (404, 405):
            async with self._session.get(self._graph_url, params=payload, timeout=timeout) as resp:
                text = await resp.text()
                status = resp.status

        try:
            return json.loads(text), status
        except json.JSONDecodeError:
            return {"error": {"message": text[:300]}}, status or 502


def verify_sync(
    access_token: str,
    attestation_token: str,
    policy: Policy,
    *,
    graph_url: str = GRAPH_VERIFY,
    timeout: int = 20,
) -> Result:
    """Blocking transport for the desktop window. Stdlib only."""
    payload = urllib.parse.urlencode(
        {"token": attestation_token.strip(), "access_token": normalize_access_token(access_token)}
    ).encode("utf-8")

    req = urllib.request.Request(graph_url, data=payload, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        status = exc.code
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return Result(False, f"transport: {exc}")

    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        body = {"error": {"message": raw[:300]}}

    if status in (404, 405):
        query = urllib.parse.urlencode(
            {"token": attestation_token.strip(), "access_token": normalize_access_token(access_token)}
        )
        try:
            with urllib.request.urlopen(f"{graph_url}?{query}", timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
                status = resp.status
        except urllib.error.HTTPError as exc:
            body = json.loads(exc.read().decode("utf-8", "replace") or "{}")
            status = exc.code
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return Result(False, f"transport: {exc}")

    return interpret_response(body, status, policy)
