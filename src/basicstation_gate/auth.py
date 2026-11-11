"""What a gateway presented, reduced to something a backend can check.

A gateway authenticates one of two ways, and both arrive on the request:

  token        the station sends the lines of its cups.key / tc.key file as
               HTTP headers (lorabasics/basicstation src/net.c,
               validateAuthToken), so a token is an `Authorization: Bearer`
               header on the CUPS POST and on the websocket upgrade.
  certificate  a TLS client certificate: from this process's own handshake,
               or, where TLS ends at a proxy, from `X-Forwarded-Tls-Client-Cert`
               (Traefik's passTLSClientCert: base64 DER without PEM
               delimiters, a chain comma-separated, URL-escaped by older
               releases).

The secret goes no further than this module: a token is hashed here and only
the hash reaches a backend.

The forwarded header is trusted only when the deployment says TLS ends at a
proxy that sets it. Traefik sets the header when a client certificate was
presented and otherwise passes on whatever the client sent, so the proxy
must clear it first. A gateway certificate is not secret; a forged header
carrying a real one would otherwise be a login.
"""

import base64
import binascii
import functools
import hashlib
import re
from urllib.parse import unquote

FORWARDED_CERT = 'X-Forwarded-Tls-Client-Cert'
DEFAULT_TOKEN_PREFIX = 'bsg_'
_MAX_HEADER = 16384


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


@functools.lru_cache
def _token_shape(prefix):
    # What `signer.mint_token` makes (43 urlsafe base64 characters after the
    # prefix), with room either side. Anything else is nobody's token here,
    # and refusing it costs no call to the backend -- which matters on
    # endpoints anyone on the internet can reach.
    return re.compile('^' + re.escape(prefix) + r'[A-Za-z0-9_-]{32,128}$')


def forwarded_der(header):
    """The leaf certificate's DER from a proxy's forwarded header, or None."""
    if not header or len(header) > _MAX_HEADER:
        return None
    text = unquote(header) if '%' in header else header
    leaf = text.split(',')[0]
    for marker in ('-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'):
        leaf = leaf.replace(marker, '')
    try:
        der = base64.b64decode(''.join(leaf.split()), validate=True)
    except (binascii.Error, ValueError):
        return None
    return der if der[:1] == b'\x30' else None


def presented(headers, peer_der=None, trust_forwarded=False, prefix=DEFAULT_TOKEN_PREFIX):
    """{'tokenHash': ...} or {'certFingerprint': ...} (SHA-256 hex), or None.

    A certificate wins over a token when both arrive: it was proven in the
    handshake, and a header can be added by anything in between.
    """
    der = peer_der
    if der is None and trust_forwarded:
        der = forwarded_der(headers.get(FORWARDED_CERT))
    if der:
        return {'certFingerprint': hashlib.sha256(der).hexdigest()}

    authorization = (headers.get('Authorization') or '').strip()
    if authorization[:7].lower() == 'bearer ':
        token = authorization[7:].strip()
    elif prefix and authorization.startswith(prefix):
        # RAK's WisGateOS asks for "Authorization: <key>" in its token field,
        # without a scheme, and a technician types exactly that. Only our own
        # prefix is taken bare, so no other header is ever read as a token.
        token = authorization
    else:
        return None
    if _token_shape(prefix).match(token):
        return {'tokenHash': token_hash(token)}
    return None
