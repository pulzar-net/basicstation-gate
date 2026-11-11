"""The signer: the one process that holds keys, and it faces nothing public.

  the client CA    signs each gateway's CUPS and LNS client certificates. A
                   certificate is accepted because its fingerprint is on the
                   backend's record, not because this CA signed it; the CA is
                   what lets a TLS terminator ask for a client certificate at
                   all, and what gateway documentation expects.
  the update key   signs update.bin for gateways that hold its sig-N.key.

The public process (gate and CUPS) asks it to mint credentials and sign
firmware over an internal listener (a unix socket or a private address) with
a bearer token, and so does your application when it issues a bundle. A
compromised public process can ask for what that process can already do; it
cannot take the keys away, and it cannot get arbitrary bytes signed: the
signer fetches firmware from the backend itself and signs only what matches
the digest the backend recorded.

A gateway private key or token is generated here, returned in the one
response that delivers it, and forgotten: the backend records only a
fingerprint or a hash.
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import logging
import os
import secrets
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import auth, cups, env

log = logging.getLogger('basicstation_gate.signer')

PURPOSES = ('cups', 'tc')


class NotConfigured(Exception):
    pass


# ── keys ─────────────────────────────────────────────────────────────────────

def _self_signed(key, common_name, ca, days=3650, san=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None),
                              critical=True))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]),
                                        critical=False)
    return builder.sign(key, hashes.SHA256())


def _write_pair(directory, stem, key, cert):
    path = directory / f'{stem}.key'
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    path.chmod(0o600)
    (directory / f'{stem}.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def dev_state(directory, hostname='localhost'):
    """Throwaway keys for trying it out, made once and kept in `directory`.

      ca.key, ca.pem          the client CA: the signer's alone
      public/server.{pem,key} a self-signed certificate for the public
                              listener, which is also the trust anchor every
                              bundle carries
      public/client-ca.pem    the CA's certificate, for CLIENT_CA_FILE

    Mount only public/ into the public process.
    """
    directory = Path(directory)
    public = directory / 'public'
    public.mkdir(parents=True, exist_ok=True)
    if not (directory / 'ca.pem').exists():
        key = ec.generate_private_key(ec.SECP256R1())
        _write_pair(directory, 'ca', key,
                    _self_signed(key, 'basicstation-gate development client CA', ca=True))
    if not (public / 'server.pem').exists():
        key = ec.generate_private_key(ec.SECP256R1())
        _write_pair(public, 'server', key, _self_signed(key, hostname, ca=True, san=hostname))
    (public / 'client-ca.pem').write_bytes((directory / 'ca.pem').read_bytes())
    return directory


class Keys:
    """Everything the signer holds, loaded once at start.

    From files (CLIENT_CA_CERT_FILE, CLIENT_CA_KEY_FILE, SIGNING_KEY_FILE,
    CUPS_TRUST_FILE, TC_TRUST_FILE), or, with DEV_STATE_DIR and nothing else
    configured, from throwaway development keys. DEV_STATE_DIR is refused
    alongside a configured CA so it cannot quietly replace a real one.
    """

    def __init__(self, ca_key, ca_cert, signing, cups_trust, tc_trust,
                 token_prefix=auth.DEFAULT_TOKEN_PREFIX, cert_days=3650,
                 cert_org='basicstation-gate'):
        self.ca_key, self.ca_cert, self.signing = ca_key, ca_cert, signing
        self.trust = {'cups': cups_trust, 'tc': tc_trust}
        self.token_prefix, self.cert_days, self.cert_org = token_prefix, cert_days, cert_org

    @classmethod
    def from_env(cls):
        def read(name):
            path = os.getenv(name)
            return Path(path).read_bytes() if path else None

        ca_key, ca_cert = read('CLIENT_CA_KEY_FILE'), read('CLIENT_CA_CERT_FILE')
        cups_trust, tc_trust = read('CUPS_TRUST_FILE'), read('TC_TRUST_FILE')
        dev = os.getenv('DEV_STATE_DIR')
        if dev:
            if ca_key or ca_cert:
                raise NotConfigured('DEV_STATE_DIR is for development only; unset it '
                                    'when CLIENT_CA_* is configured')
            state = dev_state(dev, os.getenv('DEV_HOSTNAME', 'localhost'))
            ca_key, ca_cert = (state / 'ca.key').read_bytes(), (state / 'ca.pem').read_bytes()
            cups_trust = cups_trust or (state / 'public' / 'server.pem').read_bytes()
            tc_trust = tc_trust or (state / 'public' / 'server.pem').read_bytes()
        if bool(ca_key) != bool(ca_cert):
            raise NotConfigured('CLIENT_CA_KEY_FILE and CLIENT_CA_CERT_FILE go together')
        if not (cups_trust and tc_trust):
            raise NotConfigured('CUPS_TRUST_FILE and TC_TRUST_FILE are required: the CA '
                                'that signed your public TLS certificate (e.g. ISRG Root X1)')
        signing = read('SIGNING_KEY_FILE')
        return cls(
            ca_key=serialization.load_pem_private_key(ca_key, None) if ca_key else None,
            ca_cert=x509.load_pem_x509_certificate(ca_cert) if ca_cert else None,
            signing=_signing_key(signing) if signing else None,
            cups_trust=_trust_der(cups_trust), tc_trust=_trust_der(tc_trust),
            token_prefix=env('TOKEN_PREFIX', auth.DEFAULT_TOKEN_PREFIX),
            cert_days=int(env('CERT_DAYS', '3650')),
            cert_org=env('CERT_ORG', 'basicstation-gate'))

    # Public parts ------------------------------------------------------------

    def signing_key_file(self):
        return cups.signing_key_file(self.signing.public_key()) if self.signing else None

    def signing_key_crc(self):
        raw = self.signing_key_file()
        return cups.crc32(raw) if raw else None

    # Minting -----------------------------------------------------------------

    def mint_token(self):
        return self.token_prefix + secrets.token_urlsafe(32)

    def mint_certificate(self, eui, purpose):
        """A client certificate and its key for one gateway and one purpose.

        CN is the EUI because that is what every Basics Station server,
        ChirpStack's bridge included, compares against the router id. The key
        is SEC1 DER so it fits the station's two length forms (cups.py).
        """
        if self.ca_key is None:
            raise NotConfigured('no client CA is configured; certificates cannot be issued')
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        serial = x509.random_serial_number()
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, eui),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.cert_org),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f'basic-station-{purpose}'),
                ]))
                .issuer_name(self.ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(serial)
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=self.cert_days))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                               critical=False)
                .sign(self.ca_key, hashes.SHA256()))
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        key_der = key.private_bytes(serialization.Encoding.DER,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
        return {'cert': cert_der, 'key': key_der,
                'fingerprint': hashlib.sha256(cert_der).hexdigest(),
                'serial': format(serial, 'x'), 'notAfter': cert.not_valid_after_utc.isoformat()}

    def issue(self, kind, eui, purpose):
        """One credential set: (secret, record, blob).

        `secret` holds the private key or token and goes to exactly one
        caller; `record` holds nothing that authenticates; `blob` is the CUPS
        credentials segment.
        """
        trust = self.trust[purpose]
        if kind == 'token':
            token = self.mint_token()
            data, crc = cups.blob(trust, token=token)
            secret = {'kind': 'token', 'trust': trust, 'token': token}
            record = {'kind': 'token', 'tokenHash': auth.token_hash(token)}
        elif kind == 'certificate':
            minted = self.mint_certificate(eui, purpose)
            data, crc = cups.blob(trust, cert=minted['cert'], key=minted['key'])
            secret = {'kind': 'certificate', 'trust': trust,
                      'cert': minted['cert'], 'key': minted['key']}
            record = {'kind': 'certificate', 'certFingerprint': minted['fingerprint'],
                      'certSerial': minted['serial'], 'notAfter': minted['notAfter']}
        else:
            raise ValueError(f'unknown credential kind {kind!r}')
        record.update({'purpose': purpose, 'crc': crc})
        return secret, record, data

    def sign(self, data):
        if self.signing is None:
            raise NotConfigured('no SIGNING_KEY_FILE is configured')
        return cups.sign_update(self.signing, data)


def _signing_key(pem):
    key = serialization.load_pem_private_key(pem, None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise NotConfigured('SIGNING_KEY_FILE must be an EC P-256 key; the station verifies nothing else')
    return key


def _trust_der(pem):
    """cups.trust / tc.trust: the CA that signed *our servers'* TLS
    certificates, not the client CA. A gateway checks the server with it."""
    return x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)


def pem(der, label):
    body = base64.b64encode(der).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return f'-----BEGIN {label}-----\n' + '\n'.join(lines) + f'\n-----END {label}-----\n'


def as_files(purpose, secret):
    """The secret as the files a person installs: `cups.trust`, `tc.key`, ...

    PEM rather than DER: every gateway UI that takes these accepts PEM, most
    take it pasted, and a binary file pasted into a text box is corrupted.
    """
    files = {f'{purpose}.trust': pem(secret['trust'], 'CERTIFICATE')}
    if secret['kind'] == 'token':
        files[f'{purpose}.key'] = cups.token_file(secret['token']).decode()
    else:
        files[f'{purpose}.crt'] = pem(secret['cert'], 'CERTIFICATE')
        files[f'{purpose}.key'] = pem(secret['key'], 'EC PRIVATE KEY')
    return files


def bundle(keys, eui, kind, versions=None):
    """A fresh CUPS and LNS credential set for one gateway: (files, records)."""
    files, records = {}, []
    for purpose in PURPOSES:
        secret, record, _blob = keys.issue(kind, eui, purpose)
        files.update(as_files(purpose, secret))
        # A bundle's CRC is not recorded: whoever installs it may convert it
        # to PEM, and the station reports the CRC of what is on its disk.
        record.pop('crc')
        records.append({**record, 'version': int((versions or {}).get(purpose) or 1)})
    return files, records


# ── the internal listener ────────────────────────────────────────────────────

def application(keys, token, backend=None):
    """The signer's HTTP API. Everything but /health needs `Authorization:
    Bearer <SIGNER_TOKEN>`."""
    from aiohttp import web

    from .backends import Unavailable

    signatures = {}

    @web.middleware
    async def guard(request, handler):
        if request.path != '/health':
            given = request.headers.get('Authorization', '')
            if not hmac.compare_digest(given.encode(), f'Bearer {token}'.encode()):
                return web.json_response({'error': 'Unauthorized'}, status=401)
        try:
            return await handler(request)
        except NotConfigured as e:
            return web.json_response({'error': str(e)}, status=503)
        except cups.ProtocolError as e:
            return web.json_response({'error': str(e)}, status=500)

    async def body(request):
        try:
            data = await request.json()
        except ValueError:
            data = None
        if not isinstance(data, dict):
            raise web.HTTPBadRequest(text='{"error": "body must be a JSON object"}',
                                     content_type='application/json')
        return data

    def eui_of(data):
        try:
            return cups.router_eui(data.get('gatewayId') or '')
        except cups.ProtocolError:
            raise web.HTTPBadRequest(text='{"error": "gatewayId must be a 16-digit EUI"}',
                                     content_type='application/json') from None

    def kind_of(data):
        if data.get('kind') not in ('token', 'certificate'):
            raise web.HTTPBadRequest(text='{"error": "kind must be token or certificate"}',
                                     content_type='application/json')
        return data['kind']

    async def health(_request):
        return web.json_response({'status': 'ok', 'clientCa': keys.ca_key is not None,
                                  'signingKey': keys.signing is not None})

    async def trust(_request):
        raw = keys.signing_key_file()
        return web.json_response({
            'clientCa': pem(keys.ca_cert.public_bytes(serialization.Encoding.DER), 'CERTIFICATE')
            if keys.ca_cert else None,
            'cupsTrust': pem(keys.trust['cups'], 'CERTIFICATE'),
            'tcTrust': pem(keys.trust['tc'], 'CERTIFICATE'),
            'signingKey': {'crc': cups.crc32(raw), 'file': base64.b64encode(raw).decode()}
            if raw else None,
        })

    async def credentials(request):
        """A bundle for a person to install: the one route returning a secret
        that is not on its way to a gateway over CUPS."""
        data = await body(request)
        eui, kind = eui_of(data), kind_of(data)
        files, records = bundle(keys, eui, kind, data.get('versions'))
        log.info('issued %s bundle for %s', kind, eui)
        return web.json_response({'files': files, 'records': records})

    async def mint(request):
        """One credentials segment for a CUPS answer, and its record."""
        data = await body(request)
        eui, kind = eui_of(data), kind_of(data)
        if data.get('purpose') not in PURPOSES:
            raise web.HTTPBadRequest(text='{"error": "purpose must be cups or tc"}',
                                     content_type='application/json')
        _secret, record, blob = keys.issue(kind, eui, data['purpose'])
        record['version'] = data.get('version')
        log.info('minted %s %s credential for %s', data['purpose'], kind, eui)
        return web.json_response({'credentials': base64.b64encode(blob).decode(),
                                  'record': record})

    async def sign(request):
        """A signature for firmware the backend planned, fetched and checked
        here, never bytes the caller supplies."""
        data = await body(request)
        firmware_id, digest = str(data.get('id') or ''), str(data.get('sha512') or '').lower()
        if not firmware_id or len(digest) != 128:
            raise web.HTTPBadRequest(text='{"error": "id and sha512 are required"}',
                                     content_type='application/json')
        if keys.signing is None:
            raise NotConfigured('no SIGNING_KEY_FILE is configured')
        if digest not in signatures:
            if backend is None:
                raise NotConfigured('the signer has no backend to fetch firmware from')
            try:
                update = await backend.firmware(firmware_id)
            except Unavailable as e:
                return web.json_response({'error': str(e)}, status=503)
            if hashlib.sha512(update).hexdigest() != digest:
                return web.json_response({'error': 'firmware does not match its digest'},
                                         status=502)
            if len(signatures) >= 16:
                signatures.pop(next(iter(signatures)))
            signatures[digest] = keys.sign(update)
        key_crc, signature = signatures[digest]
        return web.json_response({'keyCrc': key_crc,
                                  'signature': base64.b64encode(signature).decode()})

    app = web.Application(middlewares=[guard], client_max_size=16 * 1024)
    app.add_routes([web.get('/health', health), web.get('/trust', trust),
                    web.post('/credentials', credentials), web.post('/mint', mint),
                    web.post('/sign', sign)])
    if backend is not None:
        async def close_backend(_app):
            await backend.close()
        app.on_cleanup.append(close_backend)
    return app


def serve():
    from aiohttp import web

    token = env('SIGNER_TOKEN')
    if not token or len(token) < 16:
        raise SystemExit('SIGNER_TOKEN (16+ characters) is required')
    keys = Keys.from_env()
    backend = None
    if keys.signing is not None:
        from . import backends
        backend = backends.load()
    listen = env('SIGNER_LISTEN', '127.0.0.1:5810')
    app = application(keys, token, backend)
    log.info('signer on %s (client CA %s, signing key %s)', listen,
             'yes' if keys.ca_key else 'no',
             f'crc {keys.signing_key_crc():08x}' if keys.signing else 'no')
    if listen.startswith('unix:'):
        path = listen[5:]
        Path(path).unlink(missing_ok=True)
        old = os.umask(0o117)       # owner and group only
        try:
            web.run_app(app, path=path, print=None)
        finally:
            os.umask(old)
    else:
        host, _, port = listen.rpartition(':')
        web.run_app(app, host=host or '127.0.0.1', port=int(port), print=None)


# ── issuing a bundle by hand ─────────────────────────────────────────────────

def issue_cli(argv):
    """`basicstation-gate issue <eui>`: a bundle into a directory, and the
    lines for the file backend. Run where the signer's keys are (its
    container), with the signer's environment."""
    parser = argparse.ArgumentParser(prog='basicstation-gate issue')
    parser.add_argument('eui')
    parser.add_argument('--kind', choices=('token', 'certificate'), default='token')
    parser.add_argument('--out', help='directory for the files (default: ./<eui>)')
    parser.add_argument('--cups-uri', default=env('PUBLIC_CUPS_URI'))
    parser.add_argument('--tc-uri', default=env('PUBLIC_LNS_URI'))
    args = parser.parse_args(argv)
    eui = cups.router_eui(args.eui)
    files, records = bundle(Keys.from_env(), eui, args.kind)
    if args.cups_uri:
        files['cups.uri'] = args.cups_uri + '\n'
    if args.tc_uri:
        files['tc.uri'] = args.tc_uri + '\n'
    out = Path(args.out or eui)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        path = out / name
        path.write_text(text)
        path.chmod(0o600)
    value = 'tokenHash' if args.kind == 'token' else 'certFingerprint'
    by = {r['purpose']: r[value] for r in records}
    print(f'Wrote {", ".join(sorted(files))} to {out}/', file=sys.stderr)
    print(f'# gateways.yaml\ngateways:\n  {eui}:\n    cups: [{by["cups"]}]\n    tc: [{by["tc"]}]')
