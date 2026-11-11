"""Who decides: the record of which gateway holds which credential.

basicstation-gate keeps no state and no stored secret. Every decision -- may
this LNS connection proceed, what should this CUPS check-in get -- is a
backend's. Two ship here:

  WebhookBackend  HTTP calls to your application (docs/webhook.md). The
                  default, and the one that supports rotation, CUPS-delivered
                  credentials and firmware.
  FileBackend     a YAML file of accepted token hashes and certificate
                  fingerprints, reread when it changes. For a handful of
                  gateways: no rotation, no firmware, nothing delivered over
                  CUPS but URIs.

Your own is any class with these coroutines; name it as `BACKEND=module:Class`.
"""

import asyncio
import importlib
import logging
import os
import time

from . import USER_AGENT, env

log = logging.getLogger('basicstation_gate.backend')


class Refused(Exception):
    """The backend does not accept this credential for this gateway."""


class Unavailable(Exception):
    """The backend could not be asked, or failed. Never a yes."""


class Backend:
    """The interface. `presented` is {'tokenHash': hex} or {'certFingerprint': hex}."""

    async def authorize(self, eui, presented):
        """True if this credential may hold this gateway's LNS connection.
        Asked on connect and again every RECHECK_SECONDS while it stays open."""
        raise NotImplementedError

    async def connection(self, eui, event, peer):
        """`connected` / `disconnected`, for the record. Failures are ignored."""

    async def check_in(self, request):
        """A CUPS /update-info, authenticated by the backend. `request` is the
        parsed station report plus gatewayId, the presented credential and
        signingKeyCrc. Returns the plan: {cupsUri, tcUri, mint: {purpose:
        {kind, version}}, firmware: {id, sha512} | None}. Raises Refused or
        Unavailable."""
        raise NotImplementedError

    async def pending(self, eui, records):
        """Credentials minted for this check-in, recorded before they are sent."""
        raise Unavailable('this backend does not deliver credentials')

    async def firmware(self, firmware_id):
        """The bytes of an update the backend planned."""
        raise Unavailable('this backend has no firmware')

    async def close(self):
        pass


def same_uri(a, b):
    return (a or '').rstrip('/') == (b or '').rstrip('/')


class WebhookBackend(Backend):
    """POSTs JSON to WEBHOOK_URL/<route>. Authenticates with a static bearer
    (WEBHOOK_TOKEN) or an OAuth2 client-credentials grant (WEBHOOK_TOKEN_URL,
    WEBHOOK_CLIENT_ID, WEBHOOK_CLIENT_SECRET)."""

    def __init__(self, url, token=None, token_url=None, client_id=None, client_secret=None,
                 timeout=10.0):
        self.url = url.rstrip('/')
        self.static_token = token
        self.token_url, self.client_id, self.client_secret = token_url, client_id, client_secret
        self.timeout = timeout
        self._session = None
        self._token = (None, 0.0)
        self._token_lock = asyncio.Lock()

    @classmethod
    def from_env(cls):
        return cls(env('WEBHOOK_URL'), token=env('WEBHOOK_TOKEN'),
                   token_url=env('WEBHOOK_TOKEN_URL'), client_id=env('WEBHOOK_CLIENT_ID'),
                   client_secret=env('WEBHOOK_CLIENT_SECRET'),
                   timeout=float(env('WEBHOOK_TIMEOUT', '10')))

    def session(self):
        import aiohttp

        if self._session is None:
            # No pool limit: new handshakes are capped by the gate
            # (HANDSHAKE_CHECKS), and a shared cap would let a flood of them
            # queue live gateways' rechecks into a timeout, which reads as
            # "revoked".
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=0),
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': USER_AGENT})
        return self._session

    async def _bearer(self):
        if self.static_token:
            return self.static_token
        if not self.token_url:
            return None
        async with self._token_lock:
            value, expires = self._token
            if value and time.monotonic() < expires:
                return value
            async with self.session().post(self.token_url, data={
                    'grant_type': 'client_credentials', 'client_id': self.client_id,
                    'client_secret': self.client_secret}) as response:
                if response.status != 200:
                    raise Unavailable(f'token endpoint answered {response.status}')
                body = await response.json(content_type=None)
            value = body['access_token']
            self._token = (value, time.monotonic() + max(0, int(body.get('expires_in', 60)) - 30))
            return value

    async def _call(self, method, route, body=None):
        """(status, bytes). Raises Unavailable when no answer came."""
        import aiohttp

        try:
            bearer = await self._bearer()
            headers = {'Authorization': f'Bearer {bearer}'} if bearer else {}
            async with self.session().request(method, f'{self.url}{route}', json=body,
                                              headers=headers) as response:
                return response.status, await response.read()
        except (aiohttp.ClientError, asyncio.TimeoutError, KeyError, ValueError) as e:
            raise Unavailable(f'{route}: {e!r}') from None

    async def authorize(self, eui, presented):
        try:
            status, _ = await self._call('POST', '/authorize', {'gatewayId': eui, **presented})
        except Unavailable as e:
            # A backend that cannot be reached must not become a door that
            # opens for everyone.
            log.warning('authorize %s: %s', eui, e)
            return False
        return status == 200

    async def connection(self, eui, event, peer):
        try:
            await self._call('POST', '/connection', {'gatewayId': eui, 'event': event, 'peer': peer})
        except Unavailable as e:
            log.info('could not report %s %s: %s', eui, event, e)

    async def check_in(self, request):
        import json

        status, body = await self._call('POST', '/check-in', request)
        if status in (401, 403, 404):
            raise Refused(status)
        if status != 200:
            raise Unavailable(f'check-in answered {status}')
        try:
            plan = json.loads(body)
        except ValueError:
            raise Unavailable('check-in answer is not JSON') from None
        if not isinstance(plan, dict):
            raise Unavailable('check-in answer is not an object')
        return plan

    async def pending(self, eui, records):
        status, _ = await self._call('POST', '/pending', {'gatewayId': eui, 'records': records})
        if not 200 <= status < 300:
            raise Unavailable(f'pending answered {status}')

    async def firmware(self, firmware_id):
        status, body = await self._call('GET', f'/firmware/{firmware_id}')
        if status != 200:
            raise Unavailable(f'firmware answered {status}')
        return body

    async def close(self):
        if self._session is not None:
            await self._session.close()


class FileBackend(Backend):
    """Gateways and what they may present, from a YAML file:

        cupsUri: https://cups.example.com      # sent when the station's differs
        tcUri: wss://lns.example.com:443
        gateways:
          0123456789abcdef:
            cups: [<tokenHash or certFingerprint>, ...]
            tc: [...]

    Reread whenever its modification time changes, so deleting a line is a
    revocation: a connected gateway is dropped at its next recheck.
    """

    def __init__(self, path):
        self.path = path
        self._stamp = None
        self._data = {}

    @classmethod
    def from_env(cls):
        return cls(env('GATEWAYS_FILE', '/etc/basicstation-gate/gateways.yaml'))

    def data(self):
        import yaml

        try:
            stamp = os.stat(self.path).st_mtime_ns
        except OSError as e:
            raise Unavailable(f'{self.path}: {e}') from None
        if stamp != self._stamp:
            with open(self.path) as f:
                data = yaml.safe_load(f) or {}
            gateways = {}
            for eui, entry in (data.get('gateways') or {}).items():
                entry = entry or {}
                gateways[str(eui).lower()] = {
                    purpose: {str(v).lower() for v in entry.get(purpose) or []}
                    for purpose in ('cups', 'tc')}
            self._data = {'cupsUri': data.get('cupsUri'), 'tcUri': data.get('tcUri'),
                          'gateways': gateways}
            self._stamp = stamp
        return self._data

    def _accepts(self, eui, purpose, presented):
        try:
            held = self.data()['gateways'].get(eui, {}).get(purpose, set())
        except Unavailable as e:
            log.warning('%s', e)
            return False
        # Only the two credential fields: a check-in also carries strings the
        # station chose, and a certificate fingerprint is not a secret.
        return any(presented.get(key) in held for key in ('tokenHash', 'certFingerprint'))

    async def authorize(self, eui, presented):
        return self._accepts(eui, 'tc', presented)

    async def connection(self, eui, event, peer):
        log.info('%s %s %s', eui, event, peer or '')

    async def check_in(self, request):
        if not self._accepts(request['gatewayId'], 'cups', request):
            raise Refused()
        data = self.data()
        return {
            'cupsUri': None if same_uri(request.get('cupsUri'), data['cupsUri']) else data['cupsUri'],
            'tcUri': None if same_uri(request.get('tcUri'), data['tcUri']) else data['tcUri'],
            'mint': {}, 'firmware': None,
        }


def load():
    """The backend BACKEND names: `webhook` (the default when WEBHOOK_URL is
    set), `file`, or `module:Class` for your own (built with `from_env()` if
    it has one, else with no arguments)."""
    name = env('BACKEND') or ('webhook' if env('WEBHOOK_URL') else 'file')
    if name == 'webhook':
        if not env('WEBHOOK_URL'):
            raise SystemExit('BACKEND=webhook needs WEBHOOK_URL')
        return WebhookBackend.from_env()
    if name == 'file':
        return FileBackend.from_env()
    module, _, attr = name.partition(':')
    cls = getattr(importlib.import_module(module), attr)
    return cls.from_env() if hasattr(cls, 'from_env') else cls()
