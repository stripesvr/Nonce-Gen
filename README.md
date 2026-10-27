# quest-attest

Meta Quest attestation, end to end — issue the nonce, let the headset sign, verify at Meta,
gate the claims. No token can be minted off-device; everything here works around that one
hard constraint.

Two front ends, one gate: a **Cloudflare Worker on your own domain**, and a **Windows exe** that
runs the same flow on your LAN.

```
your side                    headset                    Meta
   |  nonce (22 chars)          |                         |
   |--------------------------->|                         |
   |            GetIntegrityToken(nonce)                  |
   |                            |--- security signals --->|
   |                            |<------ signed token ----|
   |<------- token -------------|                         |
   |--- verify(token) ---------------------------------->|
   |<------------- claims / invalid signature ------------|
   |  gate: nonce, package, cert, device state, freshness |
```

## Repository

```
web/worker.js                  hosted backend: sessions, verify, gate, pages
wrangler.toml                  KV binding + gate vars
package.json                   wrangler scripts
.github/workflows/deploy.yml   push to main -> deploy
device/QuestAttestationClient.cs  Unity client (runs on the headset)
gui.py                         Windows window (LAN listener + verify)
meta_attest.py                 graph call, claims decode, policy gate
bot.py / store.py / bridge.py  optional Discord front end, same gate
build_exe.ps1                  one-file exe build
```

## Hosted: deploy

```bash
npm install
npx wrangler kv namespace create ATTEST     # paste the id into wrangler.toml
npx wrangler secret put META_ACCESS_TOKEN   # OC|APP_ID|APP_SECRET
npx wrangler deploy
```

Custom domain: dashboard → **Workers & Pages** → `quest-attest` → **Settings → Domains &
Routes → Add custom domain**. The domain must be on Cloudflare; DNS and certificate are
automatic.

GitHub Actions deploys on push to `main` once two repo secrets exist:

```
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

`META_ACCESS_TOKEN` stays a Worker secret — never a repo secret, never in `wrangler.toml`.

### Routes

```
GET  /                  package form
POST /api/session       {package} -> {session, nonce, package}
GET  /api/session/:id   nonce + package, for the headset app
POST /api/attest        {session, token} -> verdict
GET  /api/result/:id    pending | verified | rejected (+ token, claims)
GET  /pair/:id          page that polls and flips to VERIFIED
GET  /healthz
```

## Desktop

```bash
python gui.py
powershell -ExecutionPolicy Bypass -File build_exe.ps1
```

Package name → **Get token** → pairing code → headset posts the token back → verdict in the
window. Listener binds `0.0.0.0`, first free port from 8787. `GET /pair` serves a tap-to-copy
page for the headset browser.

## Device client

Drop `device/QuestAttestationClient.cs` into a Unity project with the Meta XR Platform SDK
(v55+), put it on a GameObject, paste the pairing code, press Send. It calls
`DeviceApplicationIntegrity.GetIntegrityToken(nonce)` and posts the result back.

## Gate

- graph returns `success` (signature valid)
- `exp` in the future, not beyond the 24h ceiling
- `timestamp` within `MAX_TOKEN_AGE` (default 300s)
- `nonce` equals the issued nonce, single use
- `package_id` equals the requested package
- `app_integrity_state == StoreRecognized` when `REQUIRE_STORE=1`
- `device_integrity_state` at or above `MIN_DEVICE_INTEGRITY`
- pinned cert digests, when configured

## What this cannot do

Mint a token without a headset, produce one for a package signed by another keystore, or verify
without the app's access token. Those are the signature working.

## License

MIT — see `LICENSE`.

Built by ☠ SYSTEM BREACHED ☠ —◥꧁ SHΔDØW HΛCKΞR ꧂◤
