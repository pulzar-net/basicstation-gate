"""The CUPS wire format: what LoRa Basics Station POSTs to /update-info and
the binary answer it parses. No dependencies; `sign_update` imports
`cryptography` when called.

Written against Semtech's protocol page (https://doc.sm.tc/station/cupsproto.html)
and, where that page is silent, against the station's own parser in
lorabasics/basicstation (src/cups.c, src/sys.c, src/rt.c). Those are where
the format is actually decided, and the page leaves out three things that
break a gateway if guessed:

  - The CRC is zlib's CRC-32, chained over the three credential files in the
    order trust, cert, key (`sys_crcCred`). A file that is absent or empty
    contributes four zero bytes, not nothing. So the CRC of a token set is
    crc(trust) -> crc(00000000) -> crc("Authorization: ...").

  - A credentials blob has no delimiters. The station finds the parts by
    reading ASN.1 SEQUENCE headers (`sys_credComplete`), and its reader
    understands only the short form (one length byte) and the two-byte long
    form (0x82). A DER element whose length is 128-255 bytes is encoded 0x81
    and the station misreads it. `blob()` refuses to build one rather than
    hand a gateway credentials it will mangle; an EC key goes in SEC1 form
    (121 bytes, short form), not PKCS#8 (138 bytes, 0x81), for this reason.

  - The firmware signature is ECDSA P-256 over the SHA-512 of the update
    (`cups_verifySig`: mbedtls_sha512 then mbedtls_ecdsa_read_signature, so
    DER-encoded, at most 128 bytes). A sig-N.key on the gateway is the raw
    64-byte X||Y of the public key, and `keyCRC` is the CRC-32 of that file.

The response layout, all lengths little-endian:

    cupsUriLen 1 | cupsUri | tcUriLen 1 | tcUri
    cupsCredLen 2 | cupsCred | tcCredLen 2 | tcCred
    sigLen 4 | keyCRC 4 + sig (sigLen counts both)
    updLen 4 | updData

A zero length means "no change", so "nothing to do" is fourteen zero bytes.
The path is fixed too: the station POSTs to `/update-info` on the host in
cups.uri and ignores any path in it (`cups_update_info`).
"""

import re
import struct
import zlib

NOTHING = bytes(14)

# What the station accepts in each field (`sizelen`): 1, 2, then 4 bytes.
MAX_URI = 0xFF
MAX_CRED = 0xFFFF
# `cups_sig_t.signature` is 128 bytes.
MAX_SIG = 128


class ProtocolError(ValueError):
    """A request the station would not send, or a response it would not parse."""


def crc32(data, crc=0):
    """Basic Station's `rt_crc32`: the zlib polynomial, chainable the same way."""
    return zlib.crc32(data, crc) & 0xFFFFFFFF


def credentials_crc(trust, cert, key):
    """The CRC the station reports for a set (cupsCredCrc / tcCredCrc).

    Each argument is the bytes the station wrote to that file; an empty or
    absent part counts as four zero bytes, as `sys_crcCred` does it.
    """
    crc = 0
    for part in (trust, cert, key):
        crc = crc32(part if part else bytes(4), crc)
    return crc


def _der_length(element, name):
    """The length of a DER SEQUENCE as the station will read it, refusing the
    forms `asn1_seqlen` gets wrong."""
    if len(element) < 2 or element[0] != 0x30:
        raise ProtocolError(f'{name} is not a DER SEQUENCE')
    first = element[1]
    if first < 0x80:
        length = first + 2
    elif first == 0x82 and len(element) >= 4:
        length = ((element[2] << 8) | element[3]) + 4
    else:
        raise ProtocolError(
            f'{name} uses DER length form 0x{first:02x}, which Basic Station '
            'cannot read (only short form and 0x82)')
    if length != len(element):
        raise ProtocolError(f'{name} has trailing bytes or is truncated')
    return length


def token_file(token):
    """What tc.key / cups.key holds for token auth: header lines.

    The station sends the file's lines as HTTP headers on every request
    (`validateAuthToken` requires `Name: value`, CRLF-terminated).
    """
    if not token or any(c in token for c in '\r\n'):
        raise ProtocolError('malformed token')
    return f'Authorization: Bearer {token}\r\n'.encode()


def blob(trust, cert=None, key=None, token=None):
    """A credentials segment: trust, then cert or four zeros, then key or token.

    Returns (bytes, crc). The CRC is what the station will report for this set
    once it has written it, which is how a backend learns a delivery landed.
    """
    if (key is None) == (token is None):
        raise ProtocolError('a credential is a key or a token, not both or neither')
    if token is not None and cert is not None:
        raise ProtocolError('a token set carries no certificate')
    _der_length(trust, 'trust')
    if cert is not None:
        _der_length(cert, 'cert')
    if key is not None:
        _der_length(key, 'key')
        tail = key
    else:
        tail = token_file(token)
        # The station tells a token from a key by its first byte: 0x30 is a
        # key, 0x00 is no key, anything else is a token.
        if tail[:1] in (b'\x30', b'\x00'):
            raise ProtocolError('token would be read as a key')
    data = trust + (cert if cert is not None else bytes(4)) + tail
    if len(data) > MAX_CRED:
        raise ProtocolError('credentials exceed 65535 bytes')
    return data, credentials_crc(trust, cert, tail)


def _peek(data, offset):
    if offset + 1 >= len(data):
        raise ProtocolError('truncated credentials')
    first = data[offset + 1]
    if first & 0x80:
        return ((data[offset + 2] << 8) | data[offset + 3]) + 4
    return first + 2


def split_blob(data):
    """(trust, cert, key) split the way `sys_credComplete` splits a segment.
    `cert` is b'' for a token set; `key` is the token's header line for one."""
    trust_len = _peek(data, 0)
    _der_length(data[:trust_len], 'trust')
    offset = trust_len
    if data[offset] == 0:
        cert = b''
        offset += 4
    else:
        cert = data[offset:offset + _peek(data, offset)]
        offset += len(cert)
    rest = data[offset:]
    if rest[:1] == b'\x30':
        key = rest[:_peek(rest, 0)]
    elif rest[:1] == b'\x00':
        key = b''
    else:
        key = rest
    return data[:trust_len], cert, key


def signing_key_file(public_key):
    """sig-N.key for a P-256 public key (a `cryptography` key): raw X||Y."""
    numbers = public_key.public_numbers()
    return numbers.x.to_bytes(32, 'big') + numbers.y.to_bytes(32, 'big')


def sign_update(private_key, data):
    """(keyCRC, DER signature) for an update.bin, as `cups_verifySig` checks it."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    if not isinstance(private_key.curve, ec.SECP256R1):
        raise ProtocolError('the station verifies P-256 signatures only')
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA512()))
    if len(signature) > MAX_SIG:
        raise ProtocolError('signature exceeds the station buffer')
    return crc32(signing_key_file(private_key.public_key())), signature


def encode(cups_uri=None, tc_uri=None, cups_cred=None, tc_cred=None,
           signature=None, update=None):
    """The /update-info response body.

    `signature` is (keyCRC, sig) and only accompanies an update: the station
    hashes the update segment that follows it.
    """
    out = bytearray()
    for uri in (cups_uri, tc_uri):
        raw = (uri or '').encode()
        if len(raw) > MAX_URI:
            raise ProtocolError('URI exceeds 255 bytes')
        out += struct.pack('<B', len(raw)) + raw
    for cred in (cups_cred, tc_cred):
        cred = cred or b''
        if len(cred) > MAX_CRED:
            raise ProtocolError('credentials exceed 65535 bytes')
        out += struct.pack('<H', len(cred)) + cred
    if signature is not None and update is None:
        raise ProtocolError('a signature without an update means nothing')
    if signature is not None:
        key_crc, sig = signature
        if len(sig) > MAX_SIG:
            raise ProtocolError('signature exceeds the station buffer')
        out += struct.pack('<I', 4 + len(sig)) + struct.pack('<I', key_crc) + sig
    else:
        out += struct.pack('<I', 0)
    update = update or b''
    # The station rejects segments of 2 GB and over as negative lengths.
    if len(update) >= 0x80000000:
        raise ProtocolError('update too large')
    out += struct.pack('<I', len(update)) + update
    return bytes(out)


def decode(body):
    """The inverse of `encode`, reading as `cups_update_info` reads.

    The station's parser written down, so an encoder can be checked against
    something other than itself.
    """
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(body):
            raise ProtocolError('truncated response')
        chunk = body[pos:pos + n]
        pos += n
        return chunk

    out = {}
    for name in ('cupsUri', 'tcUri'):
        n = take(1)[0]
        out[name] = take(n).decode() if n else None
    for name in ('cupsCred', 'tcCred'):
        n = struct.unpack('<H', take(2))[0]
        out[name] = take(n) if n else None
    n = struct.unpack('<I', take(4))[0]
    if n:
        if n < 8 or n > MAX_SIG + 4:
            raise ProtocolError('illegal signature segment length')
        segment = take(n)
        out['keyCrc'] = struct.unpack('<I', segment[:4])[0]
        out['sig'] = segment[4:]
    else:
        out['keyCrc'] = out['sig'] = None
    n = struct.unpack('<I', take(4))[0]
    out['update'] = take(n) if n else None
    if pos != len(body):
        raise ProtocolError('trailing bytes')
    return out


_HEX16 = re.compile(r'^[0-9a-fA-F]{16}$')


def router_eui(value):
    """The gateway EUI (16 lowercase hex digits) from `router`, in any form a
    station sends it.

    Basic Station encodes it as an ID6 (`uj_encKVn` with '6'): four groups of
    up to four hex digits joined by colons, `::` for a run of zero groups, the
    way IPv6 compresses. Plain hex, dashed or coloned bytes, or an integer are
    accepted too, because test tools and older stations send those.
    """
    if isinstance(value, bool):
        raise ProtocolError('router is not an EUI')
    if isinstance(value, int):
        if not 0 <= value < 1 << 64:
            raise ProtocolError('router out of range')
        return f'{value:016x}'
    if not isinstance(value, str) or len(value) > 64:
        raise ProtocolError('router is not an EUI')
    text = value.strip()
    if _HEX16.match(text):
        return text.lower()
    if re.fullmatch(r'[0-9a-fA-F]{2}([-:][0-9a-fA-F]{2}){7}', text):
        return re.sub(r'[-:]', '', text).lower()
    if text.count('::') > 1 or not re.fullmatch(r'[0-9a-fA-F:]+', text):
        raise ProtocolError('router is not an EUI')
    if '::' in text:
        head, tail = text.split('::')
        head = [g for g in head.split(':') if g] if head else []
        tail = [g for g in tail.split(':') if g] if tail else []
        if len(head) + len(tail) > 3:
            raise ProtocolError('router is not an ID6')
        groups = head + ['0'] * (4 - len(head) - len(tail)) + tail
    else:
        groups = text.split(':')
        if len(groups) != 4:
            raise ProtocolError('router is not an ID6')
    if any(not 1 <= len(g) <= 4 for g in groups):
        raise ProtocolError('router is not an ID6')
    return ''.join(g.rjust(4, '0') for g in groups).lower()


def parse_request(body):
    """The fields of an update-info request, checked. Unknown fields are
    ignored, as the station ignores unknown fields; a known field of the
    wrong type is refused."""
    if not isinstance(body, dict):
        raise ProtocolError('body must be a JSON object')
    out = {'router': router_eui(body.get('router'))}
    for name in ('cupsUri', 'tcUri', 'station', 'model', 'package'):
        value = body.get(name)
        if value is not None and not isinstance(value, str):
            raise ProtocolError(f'{name} must be a string')
        out[name] = (value or '')[:255] or None
    for name in ('cupsCredCrc', 'tcCredCrc'):
        value = body.get(name)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)
                                  or not 0 <= value < 1 << 32):
            raise ProtocolError(f'{name} must be a 32-bit unsigned integer')
        out[name] = value
    keys = body.get('keys') or []
    if not isinstance(keys, list) or len(keys) > 16 or any(
            isinstance(k, bool) or not isinstance(k, int) or not 0 <= k < 1 << 32
            for k in keys):
        raise ProtocolError('keys must be a list of 32-bit CRCs')
    out['keys'] = keys
    return out
