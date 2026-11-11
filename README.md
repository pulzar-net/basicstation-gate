# basicstation-gate

A front door and CUPS server for LoRa Basics Station gateways, for
ChirpStack and any other LNS that speaks the Basics Station protocol.

- **LNS front door.** Token and client-certificate auth, revocation that
  drops live connections, and `/router-info` answered with a URI you
  configure. Accepted connections are relayed to ChirpStack Gateway Bridge
  (or any muxs) frame for frame.
- **CUPS server.** `POST /update-info`: a gateway configured with only a CUPS
  URI and a credential gets its LNS URI and credentials delivered, rotated
  without a site visit, and signed firmware if you want it.
- **Your record, not ours.** Every decision is a backend's: a webhook to your
  application, or a YAML file for a handful of gateways. Nothing secret is
  stored here.

Why it exists: ChirpStack Gateway Bridge's `basic_station` backend accepts a
client certificate whose CN matches the router id and stops there. It has no
token auth, which is what most gateway UIs make easiest. It has no
revocation, so a certificate it once accepted works until it expires. Behind
a proxy, it builds its router-info URI from `Host`. The bridge does not
implement CUPS, and there was no standalone CUPS server for ChirpStack.

Tested against **LoRa Basics Station 2.0.6** (`lorabasics/basicstation`
v2.0.6) and **ChirpStack Gateway Bridge 4.1.2**. See [Tests](#tests).

## How it fits

```
                         ┌──────────── public process (no keys) ────────────┐
gateway ─https POST /update-info──▶ CUPS ──▶ backend: check-in, pending, firmware
        ─wss  /router-info───────▶ LNS  ──▶ backend: authorize, connection
        ─wss  /gateway/<eui>─────▶ LNS  ──ws──▶ chirpstack-gateway-bridge (no TLS, internal)
                         └──────────────┬───────────────────────────────────┘
                                        │ mint, sign (bearer, internal only)
                                     signer: client CA, firmware key
                                        ▲
                     your application ──┘ issue a bundle (/credentials)
```

The gate takes the bridge's place on the internet. The bridge keeps doing
what it does (Basics Station to MQTT for ChirpStack), but listens on plain
`ws://` on a network only the gate can reach, with no TLS or CA of its own:

```toml
# chirpstack-gateway-bridge.toml
[backend]
type = "basic_station"

  [backend.basic_station]
  bind = "0.0.0.0:3001"     # reachable from the gate only
  region = "EU868"
  # ... and your concentrators, as usual
```

Point `BRIDGE_URL` at it. The gate authenticates the gateway, answers
`/router-info` itself, opens `/gateway/<eui>` on the bridge only for an
accepted gateway, and from then on passes frames both ways unchanged. Every
`RECHECK_SECONDS` it asks the backend again; a revoked gateway is
disconnected (close code 1008) and refused on reconnect. Uplinks, downlinks
and `router_config` are the bridge's, as before. If the bridge is down, a
gateway gets `503` before its websocket opens and retries.

[`examples/chirpstack-gateway-bridge.toml`](examples/chirpstack-gateway-bridge.toml)
is a complete EU868 configuration.

## Auth model

A gateway holds up to two credentials, one per **purpose**: `cups` for
`/update-info`, `tc` for the LNS. Each opens only its own service, and only
for the gateway it was issued to. Each is either:

- **a token**: `TOKEN_PREFIX` (`bsg_`) and 32 to 128 URL-safe characters,
  sent as `Authorization: Bearer <token>` (or bare `Authorization: <token>`,
  which some gateway UIs send). Anything not shaped like that is refused
  without asking the backend.
- **a client certificate**, issued by the signer's client CA. TLS can end in
  this process (`CLIENT_CA_FILE`) or at a proxy that forwards the
  certificate (`TRUST_FORWARDED_CERT`). It is accepted by its fingerprint,
  not by who signed it, which is what makes revoking one possible.

The gate reduces what was presented to `tokenHash` (SHA-256 of the token) or
`certFingerprint` (SHA-256 of the DER) and asks the backend whether that
credential may act for that gateway. The backend never sees a token, and
the gate keeps no list of its own. A backend that cannot be reached is a no.

Credentials can be issued two ways:

- **By hand**: `basicstation-gate issue <eui>` (or the signer's
  `POST /credentials`) writes a bundle (`cups.uri`, `cups.trust`,
  `cups.key`, and the same for `tc`) for someone to install. Copy the files
  to the station's home directory, or paste the URI, trust and key into the
  gateway's web UI.
- **Over CUPS** (webhook backend): a gateway installed with only a `cups`
  credential checks in, and the backend's plan says what to mint. The new
  credential is recorded as pending before the station receives it, and
  becomes current when the station uses it. Rotation is the same: mint a new
  version and keep the old one accepted until the new one shows up.

The trust a gateway receives (`cups.trust`, `tc.trust`) is the CA that signed
your *server* certificates, set with `CUPS_TRUST_FILE` / `TC_TRUST_FILE` on
the signer. For Let's Encrypt that is ISRG Root X1.

## Deploy

One image or one package, two processes. The signer holds the keys and
listens only on a private address or a unix socket. The public process is
what gateways connect to and holds no keys. Run them as separate containers
or separate users.

### Docker

```bash
docker build -t basicstation-gate .
```

`examples/compose.yaml` runs the signer, the public process, ChirpStack
Gateway Bridge and an MQTT broker, with development keys and the file
backend. Gateways reach `https://` and `wss://<host>:3001`.

```bash
cd examples
openssl rand -hex 32 > signer_token
docker compose up -d --wait
docker compose exec signer basicstation-gate issue 0123456789abcdef --out /state/bundles/0123456789abcdef
docker compose cp signer:/state/bundles/0123456789abcdef .
```

`issue` prints the lines to add to `gateways/gateways.yaml`; the gate rereads
it on change. The compose file mounts the directory rather than the file,
because an editor that saves by replacing the file would leave a
single-file mount on the old copy.

For production:

- On the signer, replace `DEV_STATE_DIR` with `CLIENT_CA_CERT_FILE`,
  `CLIENT_CA_KEY_FILE`, `CUPS_TRUST_FILE` and `TC_TRUST_FILE`.
- On the public process, use your server certificate in `TLS_CERT_FILE` and
  `TLS_KEY_FILE`, or terminate TLS at a proxy.
- Point the bridge at your broker.

The image runs as uid 10015. The command is the role: `public`, `signer` or
`issue`.

### Without Docker

Python 3.10 or later.

```bash
pip install 'basicstation-gate[server]'

# as a user that can read the keys
SIGNER_LISTEN=unix:/run/bsg/signer.sock SIGNER_TOKEN_FILE=/etc/bsg/signer_token \
  CLIENT_CA_CERT_FILE=... CLIENT_CA_KEY_FILE=... CUPS_TRUST_FILE=... TC_TRUST_FILE=... \
  basicstation-gate signer

# as a user that cannot read them
SIGNER_URL=unix:/run/bsg/signer.sock SIGNER_TOKEN_FILE=/etc/bsg/signer_token \
  PUBLIC_LNS_URI=wss://lns.example.com:443 PUBLIC_CUPS_URI=https://cups.example.com \
  BRIDGE_URL=ws://127.0.0.1:3001 TLS_CERT_FILE=... TLS_KEY_FILE=... CLIENT_CA_FILE=... \
  GATEWAYS_FILE=/etc/bsg/gateways.yaml LISTEN_PORT=443 \
  basicstation-gate public
```

The socket is created with mode 0660; put both users in its group. Under
systemd, run each as its own unit with its own `User=`.

`SERVE=lns` and `SERVE=cups` split the public process in two, so the LNS
front door never talks to the signer at all.

## Backends

| | Webhook | File |
|---|---|---|
| Token and certificate auth, per purpose | yes | yes |
| Revocation, live connections dropped | yes | yes (edit the file) |
| URIs over CUPS | yes | yes |
| Credentials delivered and rotated over CUPS | yes | no |
| Firmware over CUPS | yes | no |

The webhook contract is [docs/webhook.md](docs/webhook.md). Your own
backend is a class with the coroutines in `basicstation_gate.backends.Backend`,
named as `BACKEND=package.module:Class`.

## Configuration

Settings are environment variables. Any of them can instead be read from a
file named by `<NAME>_FILE`, which is how to pass secrets.

**Public process**

| Variable | Default | |
|---|---|---|
| `SERVE` | `lns,cups` | Which routes this process serves. Split into two processes for least privilege. |
| `PUBLIC_LNS_URI` | (required for lns) | The `wss://host:port` gateways reach the LNS on; router-info names `<this>/gateway/<eui>`. |
| `PUBLIC_CUPS_URI` | | Only adds its host to the default `ALLOWED_URI_HOSTS`. |
| `ALLOWED_URI_HOSTS` | hosts of the two above | The only hosts CUPS will point a gateway at. |
| `BRIDGE_URL` | `ws://chirpstack-gateway-bridge:3001` | The muxs that accepted connections are relayed to. |
| `SIGNER_URL`, `SIGNER_TOKEN` | (required for cups) | `http://signer:5810` or `unix:/run/bsg/signer.sock`. |
| `LISTEN_HOST`, `LISTEN_PORT` | `0.0.0.0`, `3001` | |
| `HEALTH_PORT` | `3002` | `/health`, kept off the public port. |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | | TLS in this process. Unset when a proxy terminates TLS. |
| `CLIENT_CA_FILE` | | Asks for a client certificate (optional, since token gateways present none). |
| `TRUST_FORWARDED_CERT` | `false` | Read `X-Forwarded-Tls-Client-Cert` (Traefik). Only behind a proxy that clears the header first. |
| `TOKEN_PREFIX` | `bsg_` | The shape of tokens this deployment mints. Anything else is refused unasked. |
| `RECHECK_SECONDS` | `60` | How often an open connection's credential is checked again. |
| `HANDSHAKE_CHECKS` | `16` | Concurrent backend checks for new connections; past it, 503. |
| `MUXS_NAME` | `basicstation-gate` | The `muxs` field of router-info. |
| `BACKEND` | `webhook` if `WEBHOOK_URL`, else `file` | `webhook`, `file`, or `module:Class`. |
| `WEBHOOK_URL`, `WEBHOOK_TOKEN` | | Or `WEBHOOK_TOKEN_URL`, `WEBHOOK_CLIENT_ID`, `WEBHOOK_CLIENT_SECRET`. `WEBHOOK_TIMEOUT` (10). |
| `GATEWAYS_FILE` | `/etc/basicstation-gate/gateways.yaml` | |

**Signer**

| Variable | Default | |
|---|---|---|
| `SIGNER_LISTEN` | `127.0.0.1:5810` | Or `unix:/path` (mode 0660). Never a public address. |
| `SIGNER_TOKEN` | (required) | 16+ characters. |
| `CLIENT_CA_CERT_FILE`, `CLIENT_CA_KEY_FILE` | | Signs gateway client certificates. Without these, tokens only. |
| `CUPS_TRUST_FILE`, `TC_TRUST_FILE` | (required) | The CA that signed your *server* certificates. Goes into every bundle as `cups.trust` / `tc.trust`. |
| `SIGNING_KEY_FILE` | | EC P-256 key that signs firmware. Its `sig-0.key` is in `GET /trust`. Needs a backend (`BACKEND`, as above) to fetch firmware from. |
| `TOKEN_PREFIX`, `CERT_DAYS`, `CERT_ORG` | `bsg_`, `3650`, `basicstation-gate` | |
| `DEV_STATE_DIR`, `DEV_HOSTNAME` | | Throwaway CA and self-signed server certificate for trying it out. Refused next to a configured CA. |

## Security properties

- **Separate listeners.** Gateways reach `/update-info`, `/router-info` and
  `/gateway/<eui>`, and nothing else. `/health` is on its own port. The
  signer has no public listener at all.
- **Small bodies.** `/update-info` refuses a body over 4 KB, by its declared
  length, before reading it, and refuses one with no length. LNS messages
  are capped at 256 KB.
- **Keys in a process that faces nothing public.** The client CA and the
  firmware key live in the signer. A compromised public process can ask for
  what it could already do. It cannot take the keys, and cannot get its own
  bytes signed: the signer fetches firmware from the backend itself and signs
  only what matches the recorded digest.
- **No stored secrets on the public side.** Tokens are hashed on arrival,
  certificates reduced to fingerprints, and the backend sees only those.
  Minted credentials pass through on their way to the gateway and are not
  kept.
- **Fail closed.** A backend that cannot be reached is a no. CUPS records a
  credential before sending it, and will not point a gateway at a host off
  the allow-list or at a private address.

Rate limiting is left to whatever sits in front (a proxy or load balancer).
To report a vulnerability, see [SECURITY.md](SECURITY.md).

## The wire format

`basicstation_gate.cups` is the CUPS protocol with no dependencies: `encode`
and `decode` for the `/update-info` answer, `blob` / `split_blob` for
credential segments, `credentials_crc`, `sign_update`, `router_eui` (ID6) and
`parse_request`. It covers what Semtech's protocol page leaves out and gets
wrong if guessed: the chained CRC with four zero bytes for an absent file,
the station's ASN.1 reader that takes only short-form and `0x82` lengths
(hence SEC1 keys), and ECDSA P-256 over SHA-512 with a raw 64-byte
`sig-N.key`.

```bash
pip install basicstation-gate
```

```python
from basicstation_gate import cups

body = cups.encode(tc_uri='wss://lns.example.com:443')
```

## Tests

```bash
pip install -e '.[test]'
scripts/build-station.sh   # optional: the real Basics Station, for test_station.py
pytest
scripts/compose-e2e.sh     # the image and ChirpStack Gateway Bridge; needs Docker
```

`scripts/build-station.sh` builds **lorabasics/basicstation 2.0.6**, its
`testsim` variant (a simulated radio), natively on Linux or macOS.

`tests/test_station.py` runs it against the public process over TLS, a real
signer and a webhook stand-in, once with tokens and once with certificates.
The station starts with only CUPS credentials, then:

1. gets its LNS URI and credentials over CUPS, splitting the blob as its own
   parser does;
2. connects through the gate to the bridge;
3. reports the CRC that was recorded for what it received;
4. verifies a signed `update.bin` (`ECDSA key#0 -> VERIFIED`) and runs it;
5. is dropped when its credential is revoked, and refused on reconnect.

`scripts/compose-e2e.sh` runs `examples/compose.yaml` with the same station
in front, using a bundle from `basicstation-gate issue` and the file backend.
It passes when ChirpStack Gateway Bridge reports the gateway `ONLINE` over
MQTT and the station accepts the bridge's `router_config`.

CI runs all three on every push and pull request. The request bodies the
station sent are kept in `tests/fixtures/` for the unit tests.

Not covered: real gateway hardware and vendor UIs, and radio traffic (the
testsim radio is not driven).

## License

Apache-2.0
