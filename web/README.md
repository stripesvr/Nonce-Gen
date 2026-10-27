# hosted attestation — Cloudflare Worker

The exe works on your LAN. This puts the same job on a domain, so the headset can reach it
from any network and the browser is the whole UI.

The window still can't mint a token — nothing can. What moves to the domain is the *server*
half: nonce, session, verification, claims. The headset still makes the signed call.

## Routes

```
GET  /                    package form
POST /api/session         {package} -> {session, nonce, package}
GET  /api/session/:id     nonce + package, for the headset app
POST /api/attest          {session, token} -> verdict
GET  /api/result/:id      pending | verified | rejected (+ token, claims)
GET  /pair/:id            page that polls and shows the token
GET  /healthz
```

## Deploy

```bash
cd web
npm install -g wrangler
wrangler login
wrangler kv namespace create ATTEST        # paste the id into wrangler.toml
wrangler secret put META_ACCESS_TOKEN      # OC|APP_ID|APP_SECRET
wrangler deploy
```

You get `https://quest-attest.<your-subdomain>.workers.dev`.

## Custom domain

1. Cloudflare dashboard → **Workers & Pages** → `quest-attest` → **Settings** → **Domains & Routes**.
2. **Add custom domain** → e.g. `attest.yourdomain.com`.
3. The domain must be on Cloudflare (nameservers pointed at it). The record and certificate are created for you.
4. Done — `https://attest.yourdomain.com` serves the form and the pair page.

No Cloudflare account? Any Node host works if you port the `fetch` handler — Deno Deploy and
Vercel Edge take the same shape with a different KV.

## Headset app

Point the Unity client at the domain instead of the LAN address:

```csharp
string baseUrl = "https://attest.yourdomain.com";
```

Flow: user opens `/`, types the package, gets `/pair/<id>`; the headset app calls
`GET /api/session/<id>` for `{nonce, package}`, calls `GetIntegrityToken(nonce)`, then
`POST /api/attest {session, token}`. The page flips to VERIFIED with the token and claims.

## Notes

- The nonce is burned before verification — a failed attempt still spends it.
- Sessions live 15 minutes in KV; results 1 hour.
- No shared secret on the device endpoints: the session id is 12 hex chars, single-use, and useless without a genuine Meta signature.
- `META_ACCESS_TOKEN` is a secret, never a var, never in the repo.
- GitHub Pages alone can't do this — it serves static files and can't call the graph API or hold a secret. The Worker is the backend; point the domain at it.

Built by ☠ SYSTEM BREACHED ☠ —◥꧁ SHΔDØW HΛCKΞR ꧂◤
