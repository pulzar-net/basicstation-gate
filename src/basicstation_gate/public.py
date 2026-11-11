"""The public process: what a gateway connects to. It holds no keys and no
stored secret; every decision is the backend's and every key is the signer's.

  POST /update-info  CUPS (`SERVE` includes cups). Bodies over 4 KB are
                     refused before they are read. The backend decides what
                     the gateway should get, the signer mints it, the backend
                     records it, and only then is the answer sent.
  GET /router-info   LNS discovery (`SERVE` includes lns), answered here: the
                     station's credential is checked for the router id it
                     sends, and the reply names PUBLIC_LNS_URI -- configured,
                     never built from Host.
  GET /gateway/<eui> checked the same way, then relayed to the bridge frame
                     for frame, and rechecked every RECHECK_SECONDS while open,
                     so a revocation drops a live connection.

/health answers on its own port (HEALTH_PORT), not on the public one.

Why a front at all: ChirpStack Gateway Bridge's basic_station backend checks
a client certificate's CN against the router id and stops there -- no token
auth, which most gateway UIs make easiest, and no revocation, so a
certificate it once accepted works until it expires. The bridge runs behind
this with no TLS and no CA of its own, reachable only from here.
"""

import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import ssl
import time
from pathlib import Path
from urllib.parse import urlparse

from aiohttp import ClientSession, ClientTimeout, UnixConnector, WSMsgType, web

from . import USER_AGENT, auth, backends, cups, env
from .backends import Refused, Unavailable

log = logging.getLogger('basicstation_gate')

MAX_REQUEST = 4096
# Basics Station messages are small JSON; router_config is the largest, a few KB.
MAX_MESSAGE = 256 * 1024
TIMEOUT = 10


class Busy(Exception):
    """Every handshake check is taken; the station should try again."""


class SignerError(Exception):
    pass


class Signer:
    """The signer's internal API, over a unix socket (`unix:/path`) or HTTP."""

    def __init__(self, url, token):
        self.url, self.token = url, token
        self._session = None
        self._key_crc = None

    def session(self):
        if self._session is None:
            connector = UnixConnector(self.url[5:]) if self.url.startswith('unix:') else None
            self._session = ClientSession(
                connector=connector, timeout=ClientTimeout(total=TIMEOUT),
                headers={'Authorization': f'Bearer {self.token}', 'User-Agent': USER_AGENT})
        return self._session

    def _base(self):
        return 'http://signer' if self.url.startswith('unix:') else self.url.rstrip('/')

    async def _call(self, method, path, body=None):
        try:
            async with self.session().request(method, self._base() + path, json=body) as response:
                data = await response.json(content_type=None)
                if response.status != 200:
                    raise SignerError(f'{path}: {response.status} {data}')
                return data
        except (OSError, asyncio.TimeoutError, ValueError) as e:
            raise SignerError(f'{path}: {e!r}') from None

    async def key_crc(self):
        """keyCRC of the signer's sig-N.key, which the backend compares with
        the station's `keys` before planning firmware. None if unknown."""
        if self._key_crc is None:
            try:
                key = (await self._call('GET', '/trust')).get('signingKey')
            except SignerError as e:
                log.warning('signer: %s', e)
                return None
            self._key_crc = key['crc'] if key else 0
        return self._key_crc or None

    async def mint(self, eui, purpose, kind, version):
        data = await self._call('POST', '/mint', {'gatewayId': eui, 'purpose': purpose,
                                                  'kind': kind, 'version': version})
        return base64.b64decode(data['credentials']), data['record']

    async def sign(self, entry):
        data = await self._call('POST', '/sign', {'id': entry['id'], 'sha512': entry['sha512']})
        return data['keyCrc'], base64.b64decode(data['signature'])

    async def close(self):
        if self._session is not None:
            await self._session.close()


def _peer_der(request):
    transport = request.transport
    ssl_object = transport.get_extra_info('ssl_object') if transport else None
    return ssl_object.getpeercert(binary_form=True) if ssl_object else None


def _refuse(status, reason):
    # The station logs the status line's reason and discards the body
    # (cups.c, HTTPEV_RESPONSE), so the reason is what a person reading the
    # gateway's log sees.
    return web.Response(status=status, reason=reason, text=reason + '\n')


async def _pipe(source, sink):
    async for message in source:
        if message.type == WSMsgType.TEXT:
            await sink.send_str(message.data)
        elif message.type == WSMsgType.BINARY:
            await sink.send_bytes(message.data)
        else:
            return


class Gate:
    def __init__(self, backend, signer=None, *, serve=('lns', 'cups'),
                 public_lns_uri='', bridge_url='', allowed_uri_hosts=(),
                 trust_forwarded=False, token_prefix=auth.DEFAULT_TOKEN_PREFIX,
                 recheck_seconds=60.0, handshake_checks=16, muxs='basicstation-gate'):
        self.backend, self.signer, self.serve = backend, signer, set(serve)
        self.public_lns_uri = public_lns_uri.rstrip('/')
        self.bridge_url = bridge_url.rstrip('/')
        self.allowed_uri_hosts = {h.lower() for h in allowed_uri_hosts}
        self.trust_forwarded, self.token_prefix = trust_forwarded, token_prefix
        self.recheck_seconds, self.handshake_checks = recheck_seconds, handshake_checks
        self.muxs = muxs
        self.waiting = 0
        self._firmware = {}
        self._session = None

    @classmethod
    def from_env(cls):
        serve = {s.strip() for s in env('SERVE', 'lns,cups').split(',') if s.strip()}
        if not serve or serve - {'lns', 'cups'}:
            raise SystemExit('SERVE is a comma-separated list of lns and cups')
        public_lns_uri = env('PUBLIC_LNS_URI', '')
        if 'lns' in serve and not public_lns_uri:
            raise SystemExit('PUBLIC_LNS_URI is required: the wss:// URI gateways reach this on')
        signer = None
        if 'cups' in serve:
            if not env('SIGNER_URL') or not env('SIGNER_TOKEN'):
                raise SystemExit('SERVE=cups needs SIGNER_URL and SIGNER_TOKEN')
            signer = Signer(env('SIGNER_URL'), env('SIGNER_TOKEN'))
        default_hosts = ','.join(filter(None, (urlparse(u).hostname for u in
                                               (public_lns_uri, env('PUBLIC_CUPS_URI', '')))))
        return cls(
            backends.load(), signer, serve=serve, public_lns_uri=public_lns_uri,
            bridge_url=env('BRIDGE_URL', 'ws://chirpstack-gateway-bridge:3001'),
            allowed_uri_hosts=[h.strip() for h in env('ALLOWED_URI_HOSTS', default_hosts).split(',')
                               if h.strip()],
            trust_forwarded=env('TRUST_FORWARDED_CERT', 'false').lower() == 'true',
            token_prefix=env('TOKEN_PREFIX', auth.DEFAULT_TOKEN_PREFIX),
            recheck_seconds=float(env('RECHECK_SECONDS', '60')),
            handshake_checks=int(env('HANDSHAKE_CHECKS', '16')),
            muxs=env('MUXS_NAME', 'basicstation-gate'))

    def presented(self, request):
        return auth.presented(request.headers, _peer_der(request), self.trust_forwarded,
                              self.token_prefix)

    async def authorized(self, eui, presented, live=False):
        """True only if the backend says yes. `live` for the recheck of an
        open connection, which does not count against HANDSHAKE_CHECKS:
        anyone on the internet can open handshakes with a token-shaped
        header, and each costs a backend call, so past the limit new ones
        are answered 503 -- but a flood must never delay a connected
        gateway's recheck into a false "revoked"."""
        if not live:
            if self.waiting >= self.handshake_checks:
                raise Busy()
            self.waiting += 1
        try:
            return bool(await asyncio.wait_for(self.backend.authorize(eui, presented), TIMEOUT * 1.5))
        except Exception as e:                  # noqa: BLE001 -- anything but a yes is a no
            log.warning('authorize %s failed: %r', eui, e)
            return False
        finally:
            if not live:
                self.waiting -= 1

    async def report(self, eui, event, peer=None):
        try:
            await self.backend.connection(eui, event, peer)
        except Exception as e:                  # noqa: BLE001 -- a report is not worth a connection
            log.info('could not report %s %s: %r', eui, event, e)

    # ── LNS ──────────────────────────────────────────────────────────────────

    async def router_info(self, request):
        who = self.presented(request)
        if who is None:
            return _refuse(401, 'No credential presented')
        ws = web.WebSocketResponse(max_msg_size=MAX_MESSAGE)
        await ws.prepare(request)
        try:
            message = await ws.receive(timeout=TIMEOUT)
            router = json.loads(message.data).get('router')
            eui = cups.router_eui(router)
        except (asyncio.TimeoutError, ValueError, AttributeError, TypeError):
            await ws.close(code=1002, message=b'expected {"router": ...}')
            return ws
        try:
            accepted = await self.authorized(eui, who)
        except Busy:
            # Not an `error`: that sends the station to its backup
            # credentials over what is only load.
            await ws.close(code=1013, message=b'try again later')
            return ws
        if accepted:
            answer = {'router': router, 'muxs': self.muxs,
                      'uri': f'{self.public_lns_uri}/gateway/{eui}'}
        else:
            # What the station treats as a rejection (tc.c, tc_info_request).
            log.info('refused router-info for %s from %s', eui, request.remote)
            answer = {'router': router, 'error': 'Credential not accepted'}
        await ws.send_str(json.dumps(answer))
        await ws.close()
        return ws

    async def _recheck(self, eui, who):
        while True:
            await asyncio.sleep(self.recheck_seconds)
            if not await self.authorized(eui, who, live=True):
                log.info('credential for %s no longer accepted; closing', eui)
                return

    async def gateway(self, request):
        eui = request.match_info['eui'].lower()
        who = self.presented(request)
        if who is None:
            return _refuse(401, 'No credential presented')
        try:
            if not await self.authorized(eui, who):
                log.info('refused LNS connection for %s from %s', eui, request.remote)
                return _refuse(403, 'Credential not accepted')
        except Busy:
            return _refuse(503, 'Try again later')
        try:
            upstream = await self.session().ws_connect(
                f'{self.bridge_url}/gateway/{eui}', max_msg_size=MAX_MESSAGE)
        except Exception as e:                  # noqa: BLE001 -- the gateway retries
            log.warning('bridge unreachable for %s: %r', eui, e)
            return _refuse(503, 'LNS unavailable')

        ws = web.WebSocketResponse(max_msg_size=MAX_MESSAGE)
        revoked = False
        try:
            await ws.prepare(request)
            await self.report(eui, 'connected', request.remote)
            tasks = [asyncio.ensure_future(_pipe(ws, upstream)),
                     asyncio.ensure_future(_pipe(upstream, ws)),
                     asyncio.ensure_future(self._recheck(eui, who))]
            try:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                revoked = tasks[2] in done
            finally:
                for task in tasks:
                    task.cancel()
        finally:
            await upstream.close()
            await ws.close(code=1008 if revoked else 1000,
                           message=b'credential revoked' if revoked else b'')
            await self.report(eui, 'disconnected')
        return ws

    # ── CUPS ─────────────────────────────────────────────────────────────────

    def allowed_uri(self, uri):
        """A URI CUPS may send: TLS, an allowed host, never a private address.
        Pointing a gateway somewhere new is the one thing a CUPS server can do
        that its owner cannot undo from the gateway's own UI."""
        try:
            parsed = urlparse(uri)
            host = (parsed.hostname or '').lower()
        except ValueError:
            return False
        if parsed.scheme not in ('https', 'wss') or host not in self.allowed_uri_hosts:
            return False
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            return True

    async def update_info(self, request):
        if request.content_length is None:
            return _refuse(411, 'Content-Length required')
        # Checked against the declared length before a byte is read.
        if request.content_length > MAX_REQUEST:
            return _refuse(413, 'Request too large')
        try:
            report = cups.parse_request(json.loads(await request.read()))
        except cups.ProtocolError as e:
            return _refuse(400, str(e))
        except (ValueError, web.HTTPException):
            return _refuse(400, 'Body is not JSON')

        who = self.presented(request)
        if who is None:
            return _refuse(401, 'No credential presented')
        eui = report['router']
        try:
            plan = await self.backend.check_in({**report, 'gatewayId': eui, **who,
                                                'signingKeyCrc': await self.signer.key_crc()})
        except Refused:
            log.info('check-in refused for %s', eui)
            return _refuse(403, 'Credential not accepted')
        except Exception as e:                  # noqa: BLE001
            log.warning('check-in for %s failed: %r', eui, e)
            return _refuse(503, 'Try again later')
        try:
            body = await self.answer(eui, plan)
        except (Unavailable, SignerError, cups.ProtocolError, KeyError, TypeError) as e:
            log.error('could not answer %s: %r', eui, e)
            return _refuse(503, 'Try again later')
        return web.Response(body=body, content_type='application/octet-stream')

    async def answer(self, eui, plan):
        """Mint what the plan says is due, record it, and encode the reply."""
        uris = {}
        for key in ('cupsUri', 'tcUri'):
            uri = plan.get(key)
            if uri and not self.allowed_uri(uri):
                raise cups.ProtocolError(f'refusing to send {key} {uri!r}')
            uris[key] = uri

        blobs, records = {}, []
        for purpose in ('cups', 'tc'):
            due = (plan.get('mint') or {}).get(purpose)
            if due:
                blobs[purpose], record = await self.signer.mint(
                    eui, purpose, due['kind'], due.get('version'))
                records.append(record)
        # Recorded before it is sent: a credential the gateway holds and the
        # backend has never heard of is a gateway locked out on its next
        # connect. The other way round costs nothing -- a pending credential
        # that never arrives is replaced on the next check-in.
        if records:
            await self.backend.pending(eui, records)

        signature = update = None
        if plan.get('firmware'):
            update, signature = await self.firmware(plan['firmware'])
        return cups.encode(cups_uri=uris['cupsUri'], tc_uri=uris['tcUri'],
                           cups_cred=blobs.get('cups'), tc_cred=blobs.get('tc'),
                           signature=signature, update=update)

    async def firmware(self, entry):
        """The update and its signature, fetched once per digest."""
        digest = str(entry['sha512']).lower()
        if digest not in self._firmware:
            data = await self.backend.firmware(entry['id'])
            if hashlib.sha512(data).hexdigest() != digest:
                raise Unavailable('firmware does not match its recorded digest')
            signature = await self.signer.sign(entry)
            if len(self._firmware) >= 4:
                self._firmware.pop(next(iter(self._firmware)))
            self._firmware[digest] = (data, signature)
        return self._firmware[digest]

    # ── wiring ───────────────────────────────────────────────────────────────

    def session(self):
        if self._session is None:
            self._session = ClientSession(timeout=ClientTimeout(total=None, connect=TIMEOUT),
                                          headers={'User-Agent': USER_AGENT})
        return self._session

    def application(self):
        app = web.Application(client_max_size=MAX_REQUEST)
        if 'cups' in self.serve:
            app.router.add_post('/update-info', self.update_info)
        if 'lns' in self.serve:
            app.router.add_get('/router-info', self.router_info)
            app.router.add_get(r'/gateway/{eui:[0-9A-Fa-f]{16}}', self.gateway)
        app.on_cleanup.append(self._close)
        return app

    async def _close(self, _app):
        for closable in (self._session, self.signer, self.backend):
            if closable is not None:
                await closable.close()


def tls_context():
    """None where TLS ends at a proxy; a context where this process faces
    gateways itself. CLIENT_CA_FILE asks for a client certificate without
    requiring one (a token gateway presents none); one that is presented must
    chain to it, and is then matched by fingerprint against the backend."""
    cert, key = env('TLS_CERT_FILE'), env('TLS_KEY_FILE')
    if not cert:
        return None
    # The development certificate is the signer's to make; wait for it
    # rather than come up without TLS.
    for _ in range(60):
        if Path(cert).exists() and Path(key).exists():
            break
        time.sleep(1)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    client_ca = env('CLIENT_CA_FILE')
    if client_ca:
        context.verify_mode = ssl.CERT_OPTIONAL
        context.load_verify_locations(client_ca)
    return context


async def _health(_request):
    return web.Response(text='ok\n')


async def main():
    gate = Gate.from_env()
    context = tls_context()
    port = int(env('LISTEN_PORT', '3001'))
    health = web.Application()
    health.router.add_get('/health', _health)
    runners = [web.AppRunner(gate.application(), max_line_size=2048, max_field_size=16384,
                             access_log=None),
               web.AppRunner(health, access_log=None)]
    for runner in runners:
        await runner.setup()
    await web.TCPSite(runners[0], env('LISTEN_HOST', '0.0.0.0'), port, ssl_context=context).start()
    await web.TCPSite(runners[1], env('LISTEN_HOST', '0.0.0.0'), int(env('HEALTH_PORT', '3002'))).start()
    log.info('serving %s on %s (%s)', ','.join(sorted(gate.serve)), port,
             'TLS' if context else 'TLS at a proxy')
    try:
        await asyncio.Future()
    finally:
        for runner in runners:
            await runner.cleanup()


def serve():
    asyncio.run(main())
