"""End to end with the real LoRa Basics Station (lorabasics/basicstation 2.0.6,
the testsim build that scripts/build-station.sh makes), against the public
process over TLS, a real signer, and a webhook backend stand-in that keeps a
record the way an application would.

The station starts with only cups.uri, cups.trust and a CUPS credential:

  1. CUPS delivers the LNS URI and a minted tc credential; the backend
     records it before the answer is sent.
  2. The station connects router-info, then /gateway/<eui>, and its first
     message reaches the bridge through the gate.
  3. Its next check-in reports tcCredCrc: it must equal the CRC recorded for
     what was delivered (the chained CRC, checked by the station itself).
  4. Firmware is planned: the station verifies the ECDSA/SHA-512 signature
     with sig-0.key and runs update.bin, which leaves a marker file.
  5. The tc credential is revoked: the live connection is dropped at the next
     recheck and the station's reconnect is refused.

Skipped unless the station binary is built (STATION_BIN, or
build/station/bin/station). RECORD_FIXTURES=1 rewrites
tests/fixtures/update-info-*.json from what the station sent.
"""

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from aiohttp import web
from cryptography.hazmat.primitives import serialization

from basicstation_gate import auth, cups, signer
from basicstation_gate.backends import WebhookBackend
from basicstation_gate.public import Gate, Signer, tls_context

ROOT = Path(__file__).parent.parent
STATION = Path(os.getenv('STATION_BIN', ROOT / 'build' / 'station' / 'bin' / 'station'))
EUI = '0123456789abcdef'
ID6 = '123:4567:89ab:cdef'
SIGNER_TOKEN = 's' * 32
HOOK_TOKEN = 'h' * 32

pytestmark = pytest.mark.skipif(not STATION.exists(), reason=f'no station binary at {STATION}')


class Record:
    """The application's side: credentials by purpose and state, as a webhook."""

    def __init__(self, cups_credential, kind, lns_uri):
        self.creds = [{'purpose': 'cups', 'state': 'current', 'kind': kind, **cups_credential}]
        self.kind, self.lns_uri = kind, lns_uri
        self.firmware = None
        self.events, self.checkins, self.refusals = [], [], []

    def find(self, purpose, presented):
        for c in self.creds:
            if c['purpose'] == purpose and c['state'] in ('current', 'pending') and any(
                    presented.get(k) and c.get(k) == presented[k]
                    for k in ('tokenHash', 'certFingerprint')):
                return c
        return None

    def app(self):
        async def check_in(request):
            body = await request.json()
            self.checkins.append(body)
            if not self.find('cups', body):
                return web.json_response({'error': 'Credential not accepted'}, status=403)
            for c in self.creds:
                if c['state'] == 'pending' and body.get(f"{c['purpose']}CredCrc") == c['crc']:
                    c['state'] = 'current'
            held = [c for c in self.creds if c['purpose'] == 'tc' and c['state'] != 'revoked']
            mint = {} if held else {'tc': {'kind': self.kind, 'version': 1}}
            plan = {'cupsUri': None, 'mint': mint, 'firmware': None,
                    'tcUri': None if body.get('tcUri') == self.lns_uri else self.lns_uri}
            if (self.firmware and not mint and body.get('package') != 'v1'
                    and body.get('signingKeyCrc') in body.get('keys', [])):
                plan['firmware'] = {'id': 'fw1', 'sha512': hashlib.sha512(self.firmware).hexdigest()}
            return web.json_response(plan)

        async def pending(request):
            body = await request.json()
            for record in body['records']:
                self.creds.append({**record, 'state': 'pending'})
            return web.json_response({'recorded': len(body['records'])}, status=201)

        async def authorize(request):
            body = await request.json()
            found = self.find('tc', body)
            if not found:
                self.refusals.append(body)
                return web.json_response({'error': 'Credential not accepted'}, status=403)
            found['state'] = 'current'
            return web.json_response({'allowed': True})

        async def connection(request):
            self.events.append((await request.json())['event'])
            return web.json_response({'recorded': True})

        async def firmware(_request):
            return web.Response(body=self.firmware)

        @web.middleware
        async def bearer(request, handler):
            if request.headers.get('Authorization') != f'Bearer {HOOK_TOKEN}':
                return web.json_response({}, status=401)
            return await handler(request)

        app = web.Application(middlewares=[bearer])
        app.add_routes([web.post('/check-in', check_in), web.post('/pending', pending),
                        web.post('/authorize', authorize), web.post('/connection', connection),
                        web.get('/firmware/{id}', firmware)])
        return app

    def tc(self):
        return [c for c in self.creds if c['purpose'] == 'tc']


@contextlib.asynccontextmanager
async def serving(app, ssl_context=None):
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, '127.0.0.1', 0, ssl_context=ssl_context).start()
    try:
        yield runner.addresses[0][1]
    finally:
        await runner.cleanup()


async def until(condition, what, timeout=40):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError(f'timed out waiting for {what}')
        await asyncio.sleep(0.1)


def station_conf():
    return {
        'SX1301_conf': {'lorawan_public': True, 'clksrc': 1, 'device': 'spidev',
                        'radio_0': {'type': 'SX1257', 'rssi_offset': -166.0, 'tx_enable': True},
                        'radio_1': {'type': 'SX1257', 'rssi_offset': -166.0, 'tx_enable': False}},
        'station_conf': {'routerid': ID6, 'log_file': 'stderr', 'log_level': 'DEBUG',
                         'TC_TIMEOUT': '3s', 'CUPS_CONN_TIMEOUT': '3s',
                         'CUPS_OKSYNC_INTV': '2s', 'CUPS_RESYNC_INTV': '2s'},
    }


async def run(tmp_path, monkeypatch, kind):
    dev = tmp_path / 'dev'
    signing_path = tmp_path / 'signing.pem'
    from cryptography.hazmat.primitives.asymmetric import ec
    signing_path.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    for name in ('CLIENT_CA_KEY_FILE', 'CLIENT_CA_CERT_FILE', 'CUPS_TRUST_FILE', 'TC_TRUST_FILE'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('DEV_STATE_DIR', str(dev))
    monkeypatch.setenv('SIGNING_KEY_FILE', str(signing_path))
    keys = signer.Keys.from_env()
    monkeypatch.setenv('TLS_CERT_FILE', str(dev / 'public' / 'server.pem'))
    monkeypatch.setenv('TLS_KEY_FILE', str(dev / 'public' / 'server.key'))
    monkeypatch.setenv('CLIENT_CA_FILE', str(dev / 'public' / 'client-ca.pem'))

    home = tmp_path / 'home'
    home.mkdir()
    (home / 'station.conf').write_text(json.dumps(station_conf()))
    (home / 'version.txt').write_text('v0\n')
    (home / 'sig-0.key').write_bytes(keys.signing_key_file())
    (home / 'cups.trust').write_bytes((dev / 'public' / 'server.pem').read_bytes())
    if kind == 'token':
        bootstrap = keys.mint_token()
        (home / 'cups.key').write_bytes(cups.token_file(bootstrap))
        cups_credential = {'tokenHash': auth.token_hash(bootstrap)}
    else:
        minted = keys.mint_certificate(EUI, 'cups')
        (home / 'cups.crt').write_bytes(minted['cert'])
        (home / 'cups.key').write_bytes(minted['key'])
        cups_credential = {'certFingerprint': minted['fingerprint']}

    raw_requests, frames = [], []

    @web.middleware
    async def capture(request, handler):
        if request.path == '/update-info':
            raw_requests.append(await request.read())
        return await handler(request)

    async def bridge(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        async for message in ws:
            frames.append(message.data)
        return ws

    bridge_app = web.Application()
    bridge_app.router.add_get('/gateway/{eui}', bridge)

    record = Record(cups_credential, kind, lns_uri=None)
    hook = WebhookBackend('', token=HOOK_TOKEN)
    async with serving(record.app()) as hook_port, serving(bridge_app) as bridge_port:
        hook.url = f'http://127.0.0.1:{hook_port}'
        async with serving(signer.application(keys, SIGNER_TOKEN, hook)) as signer_port:
            gate = Gate(hook, Signer(f'http://127.0.0.1:{signer_port}', SIGNER_TOKEN),
                        bridge_url=f'ws://127.0.0.1:{bridge_port}', allowed_uri_hosts=['localhost'],
                        recheck_seconds=0.3)
            app = gate.application()
            app.middlewares.append(capture)
            async with serving(app, tls_context()) as port:
                gate.public_lns_uri = record.lns_uri = f'wss://localhost:{port}'
                (home / 'cups.uri').write_text(f'https://localhost:{port}\n')
                log = open(tmp_path / 'station.log', 'w')
                station = subprocess.Popen(
                    [str(STATION), '--home', str(home), '--temp', str(tmp_path)],
                    stdout=log, stderr=subprocess.STDOUT, cwd=home)
                try:
                    await scenario(record, frames, home, kind)
                except BaseException:
                    print((tmp_path / 'station.log').read_text()[-6000:])
                    raise
                finally:
                    station.terminate()
                    station.wait(5)
                    log.close()
    return record, raw_requests


async def scenario(record, frames, home, kind):
    # 1-2: credentials over CUPS, then the LNS through the gate.
    await until(lambda: 'connected' in record.events, 'the LNS connection')
    await until(lambda: any('"msgtype":"version"' in str(f).replace(' ', '') for f in frames),
                "the station's version message at the bridge")
    delivered = record.tc()[0]
    assert delivered['kind'] == kind

    # 3: the station's own CRC of what it wrote equals the one recorded.
    await until(lambda: any(c.get('tcCredCrc') == delivered['crc'] for c in record.checkins),
                'a check-in reporting the delivered tcCredCrc')
    assert delivered['state'] == 'current'

    # 4: signed firmware, verified and run by the station.
    marker = home / 'updated.txt'
    record.firmware = f'#!/bin/sh\necho v1 > "{home}/version.txt"\necho ok > "{marker}"\n'.encode()
    await until(marker.exists, 'update.bin to run')

    # 5: revocation drops the live connection; the reconnect is refused.
    delivered['state'] = 'revoked'
    await until(lambda: 'disconnected' in record.events, 'the revoked connection to drop')
    await until(lambda: record.refusals, 'the reconnect to be refused')


def _record_fixture(kind, record, raw_requests):
    delivered = record.tc()[0]
    for raw in raw_requests:
        body = json.loads(raw)
        if body.get('tcCredCrc') == delivered['crc']:
            out = {'eui': EUI, 'station': body.get('station'), 'request': body}
            if kind == 'token':
                out['deliveredTcCrc'] = delivered['crc']
            path = ROOT / 'tests' / 'fixtures' / f'update-info-{kind}.json'
            path.write_text(json.dumps(out, indent=2) + '\n')
            return


@pytest.mark.parametrize('kind', ['token', 'certificate'])
async def test_real_station(tmp_path, monkeypatch, kind):
    record, raw_requests = await run(tmp_path, monkeypatch, kind)
    first = json.loads(raw_requests[0])
    # What a real station sends: router as ID6, its keys' CRCs, its package.
    assert first['router'] == ID6 and first['package'] == 'v0'
    assert cups.parse_request(first)['router'] == EUI
    if os.getenv('RECORD_FIXTURES'):
        _record_fixture(kind, record, raw_requests)
