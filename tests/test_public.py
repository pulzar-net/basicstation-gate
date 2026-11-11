"""The public process, the signer and the backends, in one event loop.

The bridge is a stand-in; the station is not involved (test_station.py runs
the real one).
"""

import asyncio
import base64
import contextlib
import hashlib
import json
import time

import aiohttp
import pytest
import yaml
from aiohttp import web

from basicstation_gate import auth, cups, signer
from basicstation_gate.backends import Backend, FileBackend, Refused, Unavailable, WebhookBackend
from basicstation_gate.public import Gate, Signer

EUI = '0123456789abcdef'
TOKEN = 'bsg_' + 'g' * 40
GOOD = {'Authorization': f'Bearer {TOKEN}'}
HASH = auth.token_hash(TOKEN)
SIGNER_TOKEN = 's' * 32
FIRMWARE = b'#!/bin/sh\nreboot\n'
REQUEST = {  # the shape cups.c builds (uj_encKVn: router as ID6, CRCs unsigned)
    'router': '123:4567:89ab:cdef', 'cupsUri': 'https://lns.example.com',
    'tcUri': 'wss://lns.example.com:443', 'cupsCredCrc': 1234567890, 'tcCredCrc': 987654321,
    'station': '2.0.6(rpi/std) 2022-01-04 09:13:42', 'model': 'rpi', 'package': '1.0.0',
    'keys': [],
}


@contextlib.asynccontextmanager
async def serving(app):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield f'http://127.0.0.1:{runner.addresses[0][1]}'
    finally:
        await runner.cleanup()


class Memory(Backend):
    def __init__(self, plan=None):
        self.tc = {(EUI, HASH)}
        self.cups = {(EUI, HASH)}
        self.plan = plan or {}
        self.calls = []
        self.block = None

    async def authorize(self, eui, presented):
        self.calls.append(('authorize', presented.get('tokenHash')))
        if (eui, presented.get('tokenHash')) in self.tc:
            return True
        if self.block:
            await self.block.wait()
        return False

    async def connection(self, eui, event, peer):
        self.calls.append((event, eui))

    async def check_in(self, request):
        self.calls.append(('check-in', request))
        if (request['gatewayId'], request.get('tokenHash')) not in self.cups:
            raise Refused()
        return self.plan

    async def pending(self, eui, records):
        self.calls.append(('pending', records))

    async def firmware(self, firmware_id):
        self.calls.append(('firmware', firmware_id))
        return FIRMWARE


async def bridge_app():
    async def gateway(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_str(json.dumps({'msgtype': 'router_config', 'path': request.path}))
        async for message in ws:
            await ws.send_str(f'echo:{message.data!r}')
        return ws

    app = web.Application()
    app.router.add_get('/gateway/{eui}', gateway)
    return app


async def status_of(session, url, headers):
    try:
        async with session.ws_connect(url, headers=headers):
            return 101
    except aiohttp.WSServerHandshakeError as e:
        return e.status


# ── LNS ──────────────────────────────────────────────────────────────────────

async def test_lns():
    backend = Memory()
    async with serving(await bridge_app()) as bridge:
        gate = Gate(backend, serve=('lns',), public_lns_uri='wss://lns.example:443',
                    bridge_url=bridge.replace('http', 'ws'), recheck_seconds=0.2)
        async with serving(gate.application()) as base, aiohttp.ClientSession() as s:
            base = base.replace('http', 'ws')
            bad = {'Authorization': 'Bearer bsg_' + 'x' * 40}
            assert await status_of(s, f'{base}/router-info', {}) == 401
            assert await status_of(s, f'{base}/elsewhere', GOOD) == 404
            assert await status_of(s, f'{base}/gateway/{EUI}', bad) == 403
            assert await status_of(s, f'{base}/gateway/0000000000000001', GOOD) == 403
            # A forwarded certificate is not a credential unless trusted.
            forged = {auth.FORWARDED_CERT: base64.b64encode(b'\x30\x03\x02\x01\x01').decode()}
            assert await status_of(s, f'{base}/router-info', forged) == 401

            async with s.ws_connect(f'{base}/router-info', headers=GOOD) as ws:
                await ws.send_str(json.dumps({'router': '123:4567:89ab:cdef'}))
                answer = json.loads(await ws.receive_str())
            # Configured, never built from Host.
            assert answer == {'router': '123:4567:89ab:cdef', 'muxs': 'basicstation-gate',
                              'uri': f'wss://lns.example:443/gateway/{EUI}'}

            async with s.ws_connect(f'{base}/router-info', headers=GOOD) as ws:
                await ws.send_str(json.dumps({'router': '::1'}))
                answer = json.loads(await ws.receive_str())
            assert 'error' in answer and 'uri' not in answer

            async with s.ws_connect(f'{base}/gateway/{EUI}', headers=GOOD) as ws:
                hello = json.loads(await ws.receive_str())
                assert hello == {'msgtype': 'router_config', 'path': f'/gateway/{EUI}'}
                await ws.send_str('{"msgtype":"version"}')
                assert await ws.receive_str() == "echo:'{\"msgtype\":\"version\"}'"
                await ws.send_bytes(b'\x01\x02')     # binary stays binary
                assert await ws.receive_str() == "echo:b'\\x01\\x02'"

                backend.tc.clear()                   # revoked while connected
                message = await ws.receive(timeout=2)
                assert message.type == aiohttp.WSMsgType.CLOSE and message.data == 1008
            await asyncio.sleep(0.05)
            assert ('connected', EUI) in backend.calls and ('disconnected', EUI) in backend.calls


async def test_handshake_flood_does_not_starve_rechecks():
    backend = Memory()
    async with serving(await bridge_app()) as bridge:
        gate = Gate(backend, serve=('lns',), public_lns_uri='wss://lns.example:443',
                    bridge_url=bridge.replace('http', 'ws'), recheck_seconds=0.1,
                    handshake_checks=2)
        async with serving(gate.application()) as base, aiohttp.ClientSession() as s:
            base = base.replace('http', 'ws')
            assert await status_of(s, f'{base}/gateway/{EUI}',
                                   {'Authorization': 'Bearer not-one-of-ours'}) == 401
            assert not backend.calls, 'a bearer of the wrong shape reached the backend'

            async with s.ws_connect(f'{base}/gateway/{EUI}', headers=GOOD) as ws:
                await ws.receive_str()
                backend.block = asyncio.Event()
                junk = {'Authorization': 'Bearer bsg_' + 'f' * 40}
                waiting = [asyncio.ensure_future(status_of(s, f'{base}/gateway/{EUI}', junk))
                           for _ in range(2)]
                while gate.waiting < 2:
                    await asyncio.sleep(0.01)
                assert await status_of(s, f'{base}/gateway/{EUI}', junk) == 503
                # Rechecks pass while the flood holds every handshake slot.
                await asyncio.sleep(0.5)
                await ws.send_str('still here')
                assert await ws.receive_str() == "echo:'still here'"
                backend.block.set()
                assert await asyncio.gather(*waiting) == [403, 403]


# ── CUPS, with a real signer ─────────────────────────────────────────────────

@contextlib.asynccontextmanager
async def cups_gate(keys, backend):
    async with serving(signer.application(keys, SIGNER_TOKEN, backend)) as signer_url:
        gate = Gate(backend, Signer(signer_url, SIGNER_TOKEN), serve=('cups',),
                    allowed_uri_hosts=['lns.example.com'])
        async with serving(gate.application()) as base, aiohttp.ClientSession() as s:
            yield base, s


async def post(s, url, body=None, headers=None, data=None):
    async with s.post(url, json=body, data=data, headers=headers) as response:
        return response.status, response.reason, await response.read()


async def test_cups_surface(keys):
    backend = Memory()
    async with cups_gate(keys, backend) as (base, s):
        for path in ('/health', '/trust', '/credentials', '/mint', '/sign', '/router-info'):
            async with s.post(base + path, headers=GOOD) as r:
                assert r.status == 404, path
        async with s.get(base + '/update-info', headers=GOOD) as r:
            assert r.status == 405

        assert (await post(s, f'{base}/update-info', data='x' * 5000, headers=GOOD))[0] == 413
        assert (await post(s, f'{base}/update-info', REQUEST))[0] == 401
        status, reason, _ = await post(s, f'{base}/update-info', {**REQUEST, 'router': '::1'},
                                       headers=GOOD)
        # The station logs the reason, so it says what happened.
        assert (status, reason) == (403, 'Credential not accepted')
        sent = backend.calls[-1][1]
        assert sent['tokenHash'] == HASH and TOKEN not in json.dumps(sent)
        assert sent['signingKeyCrc'] == keys.signing_key_crc()

        backend.calls.clear()
        for bearer in ('x' * 40, 'bsg_short', TOKEN + '!'):
            status, *_ = await post(s, f'{base}/update-info', REQUEST,
                                    headers={'Authorization': f'Bearer {bearer}'})
            assert status == 401, bearer
        assert not backend.calls, 'a token of the wrong shape reached the backend'
        assert (await post(s, f'{base}/update-info', {**REQUEST, 'router': 'nope'},
                           headers=GOOD))[0] == 400
        assert (await post(s, f'{base}/update-info', data='{', headers=GOOD))[0] == 400


async def test_cups_answer(keys):
    backend = Memory()
    async with cups_gate(keys, backend) as (base, s):
        status, _, body = await post(s, f'{base}/update-info', REQUEST, headers=GOOD)
        assert status == 200 and body == cups.NOTHING

        # Both sets minted and recorded before the answer, with the CRC the
        # station will report for what it receives; firmware signed.
        backend.plan = {
            'tcUri': 'wss://lns.example.com:443',
            'mint': {'cups': {'kind': 'certificate', 'version': 2},
                     'tc': {'kind': 'token', 'version': 3}},
            'firmware': {'id': 'f1', 'sha512': hashlib.sha512(FIRMWARE).hexdigest()},
        }
        backend.calls.clear()
        status, _, body = await post(s, f'{base}/update-info', REQUEST, headers=GOOD)
        assert status == 200, body
        answer = cups.decode(body)
        assert answer['tcUri'] == 'wss://lns.example.com:443' and answer['cupsUri'] is None
        names = [c[0] for c in backend.calls]
        assert names.index('pending') > names.index('check-in')
        records = {r['purpose']: r for r in dict(backend.calls)['pending']}
        assert records['cups']['version'] == 2 and records['tc']['version'] == 3

        trust, cert, key = cups.split_blob(answer['cupsCred'])
        assert records['cups']['crc'] == cups.credentials_crc(trust, cert, key)
        assert records['cups']['certFingerprint'] == hashlib.sha256(cert).hexdigest()
        assert trust == keys.trust['cups']
        trust, cert, key = cups.split_blob(answer['tcCred'])
        token = key.decode().split('Bearer ')[1].strip()
        assert records['tc']['tokenHash'] == auth.token_hash(token)
        assert records['tc']['crc'] == cups.credentials_crc(trust, cert, key)
        assert token not in json.dumps(backend.calls), 'a minted token reached the backend'

        assert answer['update'] == FIRMWARE and answer['keyCrc'] == keys.signing_key_crc()
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        keys.signing.public_key().verify(answer['sig'], FIRMWARE, ec.ECDSA(hashes.SHA512()))

        # A plan pointing a gateway at a host that is not ours is not sent.
        for uri in ('wss://10.0.0.5:443', 'wss://evil.example:443', 'ws://lns.example.com:80'):
            backend.plan = {'tcUri': uri}
            assert (await post(s, f'{base}/update-info', REQUEST, headers=GOOD))[0] == 503, uri

        # Firmware that does not match the planned digest is never sent.
        backend.plan = {'firmware': {'id': 'f2', 'sha512': '0' * 128}}
        assert (await post(s, f'{base}/update-info', REQUEST, headers=GOOD))[0] == 503


# ── the signer ───────────────────────────────────────────────────────────────

async def test_signer(keys):
    backend = Memory()
    async with serving(signer.application(keys, SIGNER_TOKEN, backend)) as base, \
            aiohttp.ClientSession() as s:
        async with s.get(f'{base}/health') as r:
            assert r.status == 200
        for path in ('/trust', '/credentials', '/mint', '/sign'):
            async with s.post(base + path, headers={'Authorization': 'Bearer nope'}) as r:
                assert r.status in (401, 405), path
            async with s.get(base + path) as r:
                assert r.status in (401, 405), path

        auth_header = {'Authorization': f'Bearer {SIGNER_TOKEN}'}
        async with s.post(f'{base}/credentials', headers=auth_header,
                          json={'gatewayId': EUI, 'kind': 'certificate',
                                'versions': {'cups': 1, 'tc': 4}}) as r:
            body = await r.json()
        assert set(body['files']) == {'cups.trust', 'cups.crt', 'cups.key',
                                      'tc.trust', 'tc.crt', 'tc.key'}
        # The private key is in the files and nowhere else.
        assert 'PRIVATE' not in json.dumps(body['records'])
        assert {r['version'] for r in body['records']} == {1, 4}
        assert all('crc' not in r for r in body['records'])

        async with s.post(f'{base}/credentials', headers=auth_header,
                          json={'gatewayId': EUI, 'kind': 'token'}) as r:
            body = await r.json()
        assert set(body['files']) == {'cups.trust', 'cups.key', 'tc.trust', 'tc.key'}
        token = body['files']['tc.key'].split('Bearer ')[1].strip()
        assert token.startswith('bsg_') and auth.presented({'Authorization': f'Bearer {token}'})
        assert any(r.get('tokenHash') == auth.token_hash(token) for r in body['records'])

        async with s.get(f'{base}/trust', headers=auth_header) as r:
            trust = await r.json()
        assert trust['signingKey']['crc'] == cups.crc32(base64.b64decode(trust['signingKey']['file']))

        async with s.post(f'{base}/sign', headers=auth_header,
                          json={'id': 'f1', 'sha512': hashlib.sha512(b'other').hexdigest()}) as r:
            assert r.status == 502, 'signed bytes that do not match the digest'
        async with s.post(f'{base}/mint', headers=auth_header,
                          json={'gatewayId': EUI, 'kind': 'token', 'purpose': 'ssh'}) as r:
            assert r.status == 400


def test_issue_cli(keys, tmp_path, capsys):
    signer.issue_cli([EUI, '--out', str(tmp_path / 'b'), '--cups-uri', 'https://c.example'])
    files = sorted(p.name for p in (tmp_path / 'b').iterdir())
    assert files == ['cups.key', 'cups.trust', 'cups.uri', 'tc.key', 'tc.trust']
    snippet = yaml.safe_load(capsys.readouterr().out)
    token = (tmp_path / 'b' / 'tc.key').read_text().split('Bearer ')[1].strip()
    assert snippet['gateways'][EUI]['tc'] == [auth.token_hash(token)]
    assert (tmp_path / 'b' / 'tc.key').stat().st_mode & 0o077 == 0


# ── backends ─────────────────────────────────────────────────────────────────

async def test_file_backend(tmp_path):
    path = tmp_path / 'gateways.yaml'
    fingerprint = 'ab' * 32
    path.write_text(yaml.safe_dump({
        'tcUri': 'wss://lns.example.com:443',
        'gateways': {EUI: {'cups': [HASH], 'tc': [HASH, fingerprint]}}}))
    backend = FileBackend(str(path))
    assert await backend.authorize(EUI, {'tokenHash': HASH})
    assert await backend.authorize(EUI, {'certFingerprint': fingerprint})
    assert not await backend.authorize('0000000000000001', {'tokenHash': HASH})

    plan = await backend.check_in({'gatewayId': EUI, 'tokenHash': HASH, 'tcUri': None})
    assert plan == {'cupsUri': None, 'tcUri': 'wss://lns.example.com:443', 'mint': {},
                    'firmware': None}
    plan = await backend.check_in({'gatewayId': EUI, 'tokenHash': HASH,
                                   'tcUri': 'wss://lns.example.com:443/'})
    assert plan['tcUri'] is None
    # A tc credential does not open CUPS, and no other field stands in for one.
    with pytest.raises(Refused):
        await backend.check_in({'gatewayId': EUI, 'certFingerprint': fingerprint})
    with pytest.raises(Refused):
        await backend.check_in({'gatewayId': EUI, 'station': HASH})

    # Editing the file is a revocation.
    time.sleep(0.01)
    path.write_text(yaml.safe_dump({'gateways': {EUI: {'tc': []}}}))
    assert not await backend.authorize(EUI, {'tokenHash': HASH})
    path.unlink()
    assert not await backend.authorize(EUI, {'tokenHash': HASH})


async def test_webhook_backend():
    seen = []

    async def token(request):
        form = await request.post()
        assert form['grant_type'] == 'client_credentials' and form['client_secret'] == 'cs'
        seen.append('token')
        return web.json_response({'access_token': 'at', 'expires_in': 300})

    async def route(request):
        assert request.headers['Authorization'] == 'Bearer at'
        body = await request.json() if request.can_read_body else None
        seen.append((request.path, body))
        if request.path.endswith('/authorize'):
            return web.json_response({}, status=200 if body['tokenHash'] == HASH else 403)
        if request.path.endswith('/check-in'):
            if body['gatewayId'] == EUI:
                return web.json_response({'mint': {}})
            return web.json_response({}, status=403 if body['gatewayId'] == '0' * 16 else 500)
        if request.path.endswith('/firmware/f1'):
            return web.Response(body=FIRMWARE)
        return web.json_response({}, status=201)

    app = web.Application()
    app.router.add_post('/token', token)
    app.router.add_route('*', '/hook/{tail:.*}', route)
    async with serving(app) as base:
        hook = WebhookBackend(f'{base}/hook', token_url=f'{base}/token', client_id='c',
                              client_secret='cs')
        try:
            assert await hook.authorize(EUI, {'tokenHash': HASH})
            assert not await hook.authorize(EUI, {'tokenHash': 'f' * 64})
            assert await hook.check_in({'gatewayId': EUI}) == {'mint': {}}
            with pytest.raises(Refused):
                await hook.check_in({'gatewayId': '0' * 16})
            with pytest.raises(Unavailable):
                await hook.check_in({'gatewayId': '1' * 16})
            await hook.pending(EUI, [{'purpose': 'tc'}])
            await hook.connection(EUI, 'connected', '1.2.3.4')
            assert await hook.firmware('f1') == FIRMWARE
            assert seen.count('token') == 1, 'the access token was not reused'
        finally:
            await hook.close()

    # Unreachable is a no, never a yes.
    down = WebhookBackend('http://127.0.0.1:9', token='t', timeout=1)
    try:
        assert not await down.authorize(EUI, {'tokenHash': HASH})
        with pytest.raises(Unavailable):
            await down.check_in({'gatewayId': EUI})
    finally:
        await down.close()


def test_load_file_backend_from_env(monkeypatch, tmp_path):
    # GATEWAYS_FILE, not BACKEND_FILE: env('BACKEND') would read that as
    # BACKEND's own file indirection.
    monkeypatch.delenv('BACKEND', raising=False)
    monkeypatch.delenv('WEBHOOK_URL', raising=False)
    monkeypatch.setenv('GATEWAYS_FILE', str(tmp_path / 'g.yaml'))
    from basicstation_gate import backends
    loaded = backends.load()
    assert isinstance(loaded, FileBackend) and loaded.path == str(tmp_path / 'g.yaml')
