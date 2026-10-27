/**
 * quest-attest worker — API half. Pages live in ./public as real HTML.
 *
 *   POST /api/session        {package}        -> {session, nonce, package}
 *   GET  /api/session/:id                     -> {nonce, package}   (headset app)
 *   POST /api/attest         {session, token} -> {ok, message}
 *   GET  /api/result/:id                      -> {status, message, claims, token}
 *   GET  /pair/:id                            -> public/pair.html
 *   GET  /*                                   -> static assets
 *
 * Secret: META_ACCESS_TOKEN (OC|APP_ID|APP_SECRET)
 * KV:     ATTEST      Assets: ASSETS (./public)
 */

const GRAPH = "https://graph.oculus.com/platform_integrity/verify";
const SESSION_TTL = 900;
const RESULT_TTL = 3600;
const VALIDITY = 86400;

export default {
  async fetch(request, env) {
    const allowOrigin = pickOrigin(request, env);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(allowOrigin) });
    }

    const res = await route(request, env);
    const out = new Response(res.body, res);
    for (const [key, value] of Object.entries(corsHeaders(allowOrigin))) out.headers.set(key, value);
    return out;
  },
};

function pickOrigin(request, env) {
  const allowed = String(env.ALLOWED_ORIGINS || "*")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (allowed.includes("*")) return "*";
  const origin = request.headers.get("Origin") || "";
  return allowed.includes(origin) ? origin : allowed[0];
}

function corsHeaders(origin) {
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "86400",
    vary: "Origin",
  };
}

async function route(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === "/healthz") return json({ ok: true });

      if (path === "/api/session" && request.method === "POST") return createSession(request, env);
      if (path.startsWith("/api/session/") && request.method === "GET") return readSession(path.split("/").pop(), env);
      if (path === "/api/attest" && request.method === "POST") return attest(request, env);
      if (path.startsWith("/api/result/") && request.method === "GET") return readResult(path.split("/").pop(), env);
      if (path.startsWith("/api/")) return json({ error: "not found" }, 404);

      if (path.startsWith("/pair/")) {
        const page = new URL("/pair.html", url).toString();
        return env.ASSETS.fetch(new Request(page, request));
      }

      return env.ASSETS.fetch(request);
    } catch (err) {
      return json({ error: String(err && err.message ? err.message : err) }, 500);
    }
}

/* ------------------------------------------------------------- sessions */

function newNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function newId() {
  return [...crypto.getRandomValues(new Uint8Array(6))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function createSession(request, env) {
  const body = await request.json().catch(() => ({}));
  const packageId = String(body.package || "").trim();
  if (!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/.test(packageId)) {
    return json({ error: "package name does not parse" }, 400);
  }

  const session = newId();
  const nonce = newNonce();
  await env.ATTEST.put(
    `s:${session}`,
    JSON.stringify({ session, nonce, package: packageId, created: Date.now(), used: false }),
    { expirationTtl: SESSION_TTL },
  );
  return json({ session, nonce, package: packageId, expires_in: SESSION_TTL });
}

async function readSession(session, env) {
  const raw = await env.ATTEST.get(`s:${session}`);
  if (!raw) return json({ error: "unknown or expired session" }, 404);
  const s = JSON.parse(raw);
  if (s.used) return json({ error: "session already used" }, 409);
  return json({ session: s.session, nonce: s.nonce, package: s.package });
}

/* -------------------------------------------------------------- attest */

async function attest(request, env) {
  const body = await request.json().catch(() => ({}));
  const session = String(body.session || "").trim();
  const token = String(body.token || "").trim();
  if (!session || !token) return json({ ok: false, message: "session and token required" }, 400);

  const key = `s:${session}`;
  const raw = await env.ATTEST.get(key);
  if (!raw) return json({ ok: false, message: "unknown or expired session" }, 410);

  const record = JSON.parse(raw);
  if (record.used) return json({ ok: false, message: "session already used" }, 409);

  // burn first: a failed verify still spends the nonce
  record.used = true;
  await env.ATTEST.put(key, JSON.stringify(record), { expirationTtl: 60 });

  const result = await verify(env, token, record);

  await env.ATTEST.put(
    `r:${session}`,
    JSON.stringify({
      status: result.verified ? "verified" : "rejected",
      message: result.message,
      claims: result.claims,
      token,
    }),
    { expirationTtl: RESULT_TTL },
  );

  return json({ ok: result.verified, message: result.message }, result.verified ? 200 : 403);
}

async function readResult(session, env) {
  const raw = await env.ATTEST.get(`r:${session}`);
  if (!raw) return json({ status: "pending" });
  return json(JSON.parse(raw));
}

/* -------------------------------------------------------------- verify */

async function verify(env, token, record) {
  if (!env.META_ACCESS_TOKEN) return { verified: false, message: "META_ACCESS_TOKEN not set" };

  const form = new URLSearchParams({ token, access_token: env.META_ACCESS_TOKEN });
  const resp = await fetch(GRAPH, { method: "POST", body: form });
  const text = await resp.text();

  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { verified: false, message: `graph returned non-json (${resp.status})` };
  }

  if (resp.status >= 400) {
    return { verified: false, message: (body.error && body.error.message) || `graph ${resp.status}` };
  }

  const first = (body.data || [])[0];
  if (!first) return { verified: false, message: "empty graph response" };
  if (first.message !== "success") return { verified: false, message: first.message || "verification rejected" };
  if (!first.claims) return { verified: false, message: "success without claims" };

  let claims;
  try {
    claims = JSON.parse(b64urlDecode(first.claims));
  } catch {
    return { verified: false, message: "claims decode failed" };
  }

  return gate(claims, record, env);
}

function gate(claims, record, env) {
  const failures = [];
  const warnings = [];
  const req = claims.request_details || {};
  const app = claims.app_state || {};
  const dev = claims.device_state || {};
  const now = Math.floor(Date.now() / 1000);

  const maxAge = Number(env.MAX_TOKEN_AGE || 300);
  const minDevice = env.MIN_DEVICE_INTEGRITY || "Basic";
  const requireStore = (env.REQUIRE_STORE || "1") === "1";
  const order = { Advanced: 2, Basic: 1, NotTrusted: 0 };

  const exp = Number(req.exp || 0);
  if (exp <= now) failures.push("token expired");
  if (exp - now > VALIDITY + 60) failures.push("exp beyond 24h ceiling");

  const age = now - Number(req.timestamp || 0);
  if (age > maxAge) failures.push(`timestamp ${age}s old (max ${maxAge}s)`);
  if (age < -60) failures.push("timestamp in the future");

  if (req.nonce !== record.nonce) failures.push("nonce mismatch");
  if (app.package_id !== record.package) failures.push(`package_id ${app.package_id} != ${record.package}`);

  if (requireStore && app.app_integrity_state !== "StoreRecognized") {
    failures.push(`app_integrity_state ${app.app_integrity_state}`);
  }
  if ((order[dev.device_integrity_state] ?? -1) < (order[minDevice] ?? 1)) {
    failures.push(`device_integrity_state ${dev.device_integrity_state}`);
  } else if (dev.device_integrity_state === "Basic") {
    warnings.push("device integrity Basic");
  }
  if (typeof dev.security_update_pending_days === "number" && dev.security_update_pending_days > 90) {
    warnings.push(`security patch pending ${dev.security_update_pending_days}d`);
  }
  if (claims.device_ban && claims.device_ban.is_banned) warnings.push("device_ban active");

  return {
    verified: failures.length === 0,
    message: failures.length ? failures.join("; ") : "verified",
    claims,
    warnings,
  };
}

function b64urlDecode(s) {
  const normal = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normal + "=".repeat((4 - (normal.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
