# microservice-idp

A stub OpenID Connect provider — the identity sibling of `microservice-sms` / `microservice-push`
/ `microservice-image`. Framework-free Python (stdlib only). It exists so the compose stack can
demonstrate **"Sign in with Google" without Google**: `microservice-security` walks the exact same
Authorization Code + PKCE dance against this stub as against a real provider; only its configured
URLs differ.

```
GET  /authorize?client_id&redirect_uri&state&nonce&code_challenge&code_challenge_method=S256
        -> a "who are you" HTML form; with &email= it redirects immediately (automation/smoke)
POST /token      (code, code_verifier, client_id, client_secret, redirect_uri)
        -> {"access_token", "id_token", "token_type", "expires_in"}
GET  /userinfo   (Authorization: Bearer <access_token>)  -> {"sub", "email", "email_verified"}
GET  /health
```

The stub vouches for **any** email typed into it (`email_verified: true`) — that is the point: it
plays the trusted provider so account creation, linking and sign-in can be exercised end to end.
The `id_token` is an HS256 JWS keyed with the client secret (what OIDC prescribes for a
confidential client without an asymmetric keypair). Codes are single-use with a 5-minute TTL;
PKCE is S256-only.

Config (env): `PORT` (8090), `IDP_ISSUER`, `IDP_CLIENT_ID` (`demo-client`),
`IDP_CLIENT_SECRET` (`demo-secret`).

```bash
python3 server.py                 # :8090
python3 -m unittest test_server
```
