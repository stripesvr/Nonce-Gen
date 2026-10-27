# Security

## Secrets

| name | where | format |
|---|---|---|
| `META_ACCESS_TOKEN` | Worker secret (`wrangler secret put`) | `OC\|APP_ID\|APP_SECRET` |
| `CLOUDFLARE_API_TOKEN` | GitHub repo secret | Workers edit token |
| `CLOUDFLARE_ACCOUNT_ID` | GitHub repo secret | account id |

Nothing here contains a credential. `.gitignore` covers `.env`, `.dev.vars`, local sqlite, and
build output.

## Model

- The attestation token is signed by Meta. No code here can create one, and none claims to.
- The nonce is 128 bits from `crypto.getRandomValues`, single use, burned before verification.
- Sessions are 12 hex chars, 15-minute TTL, and useless without a genuine Meta signature.
- The access token never leaves the server; verification is server-side by design.
- Claims are gated on nonce, package, freshness, `exp`, store state, device trust, and pinned
  cert digests when configured.

## Reporting

Open an issue for anything that is not a live credential. For a leaked secret, rotate first:
`wrangler secret put META_ACCESS_TOKEN`, then revoke it in the Meta dashboard.

Built by ☠ SYSTEM BREACHED ☠ —◥꧁ SHΔDØW HΛCKΞR ꧂◤
