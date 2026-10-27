from __future__ import annotations

import json
import logging

from aiohttp import web

log = logging.getLogger("bridge")


def build_bridge(*, store, secret: str, on_token):
    """on_token(record: dict, token: str) -> awaitable[(bool, str)]"""

    async def attest(request: web.Request) -> web.Response:
        if request.headers.get("X-Bridge-Secret") != secret:
            raise web.HTTPUnauthorized(text="bad secret")

        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="json body required")

        nonce = str(body.get("nonce", "")).strip()
        token = str(body.get("token", "")).strip()
        if not nonce or not token:
            raise web.HTTPBadRequest(text="nonce and token required")

        record = store.lookup(nonce)
        if record is None:
            raise web.HTTPGone(text="nonce unknown, spent, or expired")

        package = str(body.get("package_id", "")).strip()
        if package and package != record["package_id"]:
            raise web.HTTPBadRequest(text="package_id does not match the issued nonce")

        ok, message = await on_token(record, token)
        return web.json_response(
            {"ok": ok, "message": message},
            status=200 if ok else 403,
        )

    async def healthz(_: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    app = web.Application(client_max_size=256 * 1024)
    app.router.add_post("/v1/attest", attest)
    app.router.add_get("/healthz", healthz)
    return app
