# The webhook backend

basicstation-gate keeps no record of its own. With `BACKEND=webhook` it asks
your application over HTTP, at five routes under `WEBHOOK_URL`. Your
application keeps the record: which gateway holds which credential, in which
state, and what it should get next.

Every request carries `Authorization: Bearer <token>` and
`User-Agent: basicstation-gate/<version>`. The token is `WEBHOOK_TOKEN`, or one
obtained with the OAuth2 client-credentials grant from `WEBHOOK_TOKEN_URL`
(`WEBHOOK_CLIENT_ID`, `WEBHOOK_CLIENT_SECRET`) and reused until 30 seconds
before it expires. Give the public LNS process, the public CUPS process and
the signer separate clients if you split them: each needs only its own routes.

| Route | Called by | When |
|---|---|---|
| `POST /authorize` | LNS | each `/router-info` and `/gateway/<eui>`, and every `RECHECK_SECONDS` while connected |
| `POST /connection` | LNS | a gateway connected or disconnected |
| `POST /check-in` | CUPS | each `/update-info` |
| `POST /pending` | CUPS | after minting credentials, before answering the station |
| `GET /firmware/<id>` | CUPS and the signer | firmware a check-in planned |

Timeouts are `WEBHOOK_TIMEOUT` seconds (10). A timeout, a refused connection
or an unexpected status is never a yes.

## What a gateway presents

Requests that authenticate a gateway carry exactly one of:

- `tokenHash`: the SHA-256 (hex) of the token from `Authorization: Bearer
  <token>`. The token itself never leaves the public process.
- `certFingerprint`: the SHA-256 (hex) of the client certificate's DER, from
  the TLS handshake (or `X-Forwarded-Tls-Client-Cert` with
  `TRUST_FORWARDED_CERT=true`). Accept a certificate by this fingerprint, not
  by who signed it: that is what makes revocation work.

A bearer not shaped like `TOKEN_PREFIX` plus 32 to 128 URL-safe characters is
refused before your application is asked.

Credentials are per purpose. A `cups` credential opens CUPS only, a `tc`
credential the LNS only, each only for the gateway it was issued to.

## `POST /authorize`

```json
{"gatewayId": "0123456789abcdef", "tokenHash": "9f86d0…"}
```

`200` lets the connection proceed; anything else refuses it. When you refuse
an open connection's recheck, the gate closes it with code 1008. A good
moment to promote a pending `tc` credential to current is the first time it
is accepted here.

At most `HANDSHAKE_CHECKS` (16) of these are outstanding for new connections;
further handshakes get `503` without a call. Rechecks of open connections do
not count against that limit.

## `POST /connection`

```json
{"gatewayId": "0123456789abcdef", "event": "connected", "peer": "203.0.113.7"}
```

`event` is `connected` or `disconnected` (with `peer` null). The answer is
ignored.

## `POST /check-in`

The station's report, parsed and checked, plus who it is:

```json
{
  "gatewayId": "0123456789abcdef",
  "router": "0123456789abcdef",
  "tokenHash": "9f86d0…",
  "cupsUri": "https://cups.example.com",
  "tcUri": "wss://lns.example.com:443",
  "cupsCredCrc": 2372069036,
  "tcCredCrc": 4088912109,
  "station": "2.0.6(linux/std) 2022-01-18 09:22:16",
  "model": "linux",
  "package": "1.0.0",
  "keys": [3523640901],
  "signingKeyCrc": 3523640901
}
```

- `cupsCredCrc` / `tcCredCrc`: the CRC-32 of the credentials the station holds
  now. Compare them with the `crc` of a pending record to learn a delivery
  landed.
- `keys`: the CRC-32 of each `sig-N.key` the station holds; `signingKeyCrc`
  is the signer's (null without a signing key). Plan firmware only when
  `keys` contains it, or the station downloads the update and discards it.

Answer `200` with the plan; every field may be left out:

```json
{
  "cupsUri": null,
  "tcUri": "wss://lns.example.com:443",
  "mint": {"tc": {"kind": "token", "version": 2}},
  "firmware": null
}
```

- `cupsUri`, `tcUri`: a URI to send, or null to leave the station's alone.
  Only `https`/`wss` URIs on `ALLOWED_URI_HOSTS` are sent (by default the
  hosts of `PUBLIC_LNS_URI` and `PUBLIC_CUPS_URI`); anything else fails the
  check-in with `503` instead of redirecting a gateway.
- `mint`: per purpose (`cups`, `tc`), a credential to issue and deliver now:
  `kind` is `token` or `certificate`, `version` is yours and comes back in
  the record.
- `firmware`: `{"id": "...", "sha512": "<hex>"}`. The update is fetched from
  `GET /firmware/<id>`, checked against the digest, signed by the signer and
  sent. Do not plan firmware in the same answer as new credentials: a gateway
  that fails an update should not also have just changed how it
  authenticates.

`401`, `403` or `404` refuse the gateway: the station gets `403 Credential not
accepted` and falls back to its backup credentials. Any other status, or no
answer, gives the station `503` and it retries.

## `POST /pending`

What was minted for the check-in that just happened, sent before the station
gets it:

```json
{
  "gatewayId": "0123456789abcdef",
  "records": [
    {"purpose": "tc", "kind": "token", "version": 2, "crc": 1838014526,
     "tokenHash": "60303a…"},
    {"purpose": "cups", "kind": "certificate", "version": 3, "crc": 911264803,
     "certFingerprint": "d2a1…", "certSerial": "5f3a…", "notAfter": "2036-11-08T09:08:45+00:00"}
  ]
}
```

Answer `2xx` once it is stored. Anything else and the station gets `503`
instead of the credentials, so a gateway never holds a credential you have
not recorded. Store new records as pending and keep accepting the current
ones: the gateway switches when it has written the new files. A pending
record is confirmed when it is used (`/authorize`, or a check-in presenting
it) or when a check-in reports its `crc`. One that is never confirmed was
lost; mint another at the next check-in.

## `GET /firmware/<id>`

`200` with the update's bytes (`application/octet-stream`). It runs as root
on the gateway after the station verifies the signature.

## The signer's API

Your application calls the signer to issue a bundle a person installs by
hand. It listens on `SIGNER_LISTEN` (a private address, or `unix:/path`) and
wants `Authorization: Bearer <SIGNER_TOKEN>`.

| Route | Body | Answer |
|---|---|---|
| `POST /credentials` | `{"gatewayId", "kind", "versions": {"cups": 1, "tc": 1}}` | `{"files": {"cups.trust": PEM, "cups.key": …}, "records": [...]}` |
| `GET /trust` | | `{"clientCa", "cupsTrust", "tcTrust", "signingKey": {"crc", "file"}}` |
| `GET /health` | | no token needed |

`files` holds the only copy of the private key or token: hand it to the
person who asked and keep only `records`. `/mint` and `/sign` are the public
process's.
