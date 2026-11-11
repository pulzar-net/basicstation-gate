"""The wire format and credential parsing, against the protocol page, the
station's own parser (cups.c, sys.c), and requests a real station sent
(fixtures/, recorded by test_station.py from lorabasics/basicstation 2.0.6)."""

import base64
import hashlib
import json
import os
import zlib
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

from basicstation_gate import auth, cups

FIXTURES = Path(__file__).parent / 'fixtures'
EUI = '0123456789abcdef'


def test_layout_byte_for_byte():
    assert cups.encode() == bytes(14) == cups.NOTHING

    # Field by field from the spec table, little-endian lengths.
    cups_uri, tc_uri = 'https://cups.example1', 'wss://lns.example:443'
    cred = b'\x30\x03\x02\x01\x07' + bytes(4) + b'Authorization: Bearer x\r\n'
    update = b'#!/bin/sh\necho hi\n'
    sig = b'\x30' + b'S' * 69
    expected = (
        bytes([len(cups_uri)]) + cups_uri.encode()
        + bytes([len(tc_uri)]) + tc_uri.encode()
        + b'\x00\x00'                                       # cupsCredLen 0
        + len(cred).to_bytes(2, 'little') + cred            # tcCredLen, tcCred
        + (4 + len(sig)).to_bytes(4, 'little')              # sigLen
        + (0xDEADBEEF).to_bytes(4, 'little') + sig          # keyCRC, sig
        + len(update).to_bytes(4, 'little') + update        # updLen, updData
    )
    got = cups.encode(cups_uri=cups_uri, tc_uri=tc_uri, tc_cred=cred,
                      signature=(0xDEADBEEF, sig), update=update)
    assert got == expected

    back = cups.decode(got)
    assert back['cupsUri'] == cups_uri and back['tcUri'] == tc_uri
    assert back['cupsCred'] is None and back['tcCred'] == cred
    assert back['keyCrc'] == 0xDEADBEEF and back['sig'] == sig and back['update'] == update


@pytest.mark.parametrize('bad', [dict(cups_uri='x' * 256), dict(tc_cred=b'x' * 65536),
                                 dict(signature=(1, b'\x30' * 10)),
                                 dict(signature=(1, b'\x30' * 129), update=b'x')])
def test_encode_refuses(bad):
    with pytest.raises(cups.ProtocolError):
        cups.encode(**bad)


def test_decode_refuses_truncated_or_padded():
    body = cups.encode(tc_uri='wss://a:1')
    for bad in (body[:-1], body + b'\x00', b'\x00' * 13):
        with pytest.raises(cups.ProtocolError):
            cups.decode(bad)


def test_crc():
    # The CRC-32 check value, and rt_crc32 chaining as zlib does.
    assert cups.crc32(b'123456789') == 0xCBF43926
    assert cups.crc32(b'6789', cups.crc32(b'12345')) == 0xCBF43926
    # sys_crcCred: an absent cert counts as four zero bytes, not as nothing.
    trust, key = b'\x30\x01\x00', b'Authorization: Bearer abc\r\n'
    assert cups.credentials_crc(trust, b'', key) == zlib.crc32(trust + bytes(4) + key)
    assert cups.credentials_crc(trust, b'', key) != zlib.crc32(trust + key)
    assert cups.credentials_crc(b'', b'', b'') == zlib.crc32(bytes(12))


def _short(n):
    return b'\x30' + bytes([n]) + bytes(n)


LONG = b'\x30\x82' + (300).to_bytes(2, 'big') + bytes(300)
# 0x81 is legal DER, and the station's asn1_seqlen misreads it.
MID = b'\x30\x81\xc8' + bytes(200)


def test_der_forms():
    cups.blob(_short(10), token='abcdefghijklmnop')
    cups.blob(LONG, token='abcdefghijklmnop')
    for args in (dict(trust=MID, token='t' * 20),
                 dict(trust=LONG, cert=MID, key=_short(5)),
                 dict(trust=LONG, cert=LONG, key=MID)):
        with pytest.raises(cups.ProtocolError):
            cups.blob(**args)


def test_token_blob_splits_where_the_station_splits():
    trust = _short(40)
    data, crc = cups.blob(trust, token='bsg_abcdefghijklmnop')
    got_trust, cert, key = cups.split_blob(data)
    assert got_trust == trust and cert == b''
    assert key == b'Authorization: Bearer bsg_abcdefghijklmnop\r\n'
    assert crc == cups.credentials_crc(trust, b'', key)


def test_minted_certificate_fits_the_station(keys):
    minted = keys.mint_certificate(EUI, 'tc')
    assert minted['cert'][1] == 0x82, 'certificate is not in 0x82 form'
    assert minted['key'][1] < 0x80, 'SEC1 key is not in short form'
    data, crc = cups.blob(keys.trust['tc'], cert=minted['cert'], key=minted['key'])
    assert cups.split_blob(data) == (keys.trust['tc'], minted['cert'], minted['key'])
    assert crc == cups.credentials_crc(keys.trust['tc'], minted['cert'], minted['key'])

    cert = x509.load_der_x509_certificate(minted['cert'])
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == EUI
    cert.verify_directly_issued_by(keys.ca_cert)
    assert minted['fingerprint'] == hashlib.sha256(minted['cert']).hexdigest()


def test_signature_verifies_as_the_station_verifies():
    signing = ec.generate_private_key(ec.SECP256R1())
    update = os.urandom(5000)
    key_crc, sig = cups.sign_update(signing, update)
    raw = cups.signing_key_file(signing.public_key())
    assert len(raw) == 64 and key_crc == zlib.crc32(raw)
    # The station hashes with SHA-512 and hands the 64-byte digest to
    # mbedtls_ecdsa_read_signature.
    public = ec.EllipticCurvePublicNumbers(int.from_bytes(raw[:32], 'big'),
                                           int.from_bytes(raw[32:], 'big'),
                                           ec.SECP256R1()).public_key()
    prehashed = ec.ECDSA(utils.Prehashed(hashes.SHA512()))
    public.verify(sig, hashlib.sha512(update).digest(), prehashed)
    with pytest.raises(InvalidSignature):
        public.verify(sig, hashlib.sha512(update + b'x').digest(), prehashed)
    assert 8 <= 4 + len(sig) <= 132

    with pytest.raises(cups.ProtocolError):
        cups.sign_update(ec.generate_private_key(ec.SECP384R1()), update)


@pytest.mark.parametrize('value,eui', [
    ('123:4567:89ab:cdef', '0123456789abcdef'), ('::1', '0000000000000001'),
    ('1::', '0001000000000000'), ('::', '0000000000000000'), ('1::2', '0001000000000002'),
    ('01-23-45-67-89-AB-CD-EF', '0123456789abcdef'), ('0123456789ABCDEF', '0123456789abcdef'),
    (0x0102030405060708, '0102030405060708'),
])
def test_router(value, eui):
    assert cups.router_eui(value) == eui


@pytest.mark.parametrize('bad', ['1:2:3', '1:2:3:4:5', '::1::', 'zz::', True, -1, None,
                                 '12345::1', 1 << 64])
def test_router_refuses(bad):
    with pytest.raises(cups.ProtocolError):
        cups.router_eui(bad)


def _recorded():
    return sorted(FIXTURES.glob('update-info-*.json'))


@pytest.mark.parametrize('path', _recorded(), ids=lambda p: p.stem)
def test_real_station_requests_parse(path):
    """What lorabasics/basicstation actually sent, and the CRC it reported for
    credentials this server delivered."""
    recorded = json.loads(path.read_text())
    report = cups.parse_request(recorded['request'])
    assert report['router'] == recorded['eui']
    # The station reported the CRC this server recorded for what it delivered.
    assert report['tcCredCrc'] == recorded.get('deliveredTcCrc', report['tcCredCrc'])
    assert recorded['station'].startswith('2.0.6')


def test_fixtures_exist():
    # Recorded by `RECORD_FIXTURES=1 pytest tests/test_station.py`; checked in.
    assert _recorded(), 'no recorded station requests in tests/fixtures'


@pytest.mark.parametrize('bad', [[], {'router': 'x'}, {'router': '::1', 'cupsCredCrc': -1},
                                 {'router': '::1', 'cupsCredCrc': True},
                                 {'router': '::1', 'keys': ['a']},
                                 {'router': '::1', 'keys': list(range(17))},
                                 {'router': '::1', 'model': 5}])
def test_parse_request_refuses(bad):
    with pytest.raises(cups.ProtocolError):
        cups.parse_request(bad)


# ── what a gateway presented ────────────────────────────────────────────────

TOKEN = 'bsg_' + 'a' * 40


def test_bearer_token_is_hashed():
    assert auth.presented({'Authorization': f'Bearer {TOKEN}'}) == {
        'tokenHash': hashlib.sha256(TOKEN.encode()).hexdigest()}


def test_bare_token_only_with_our_prefix():
    # RAK WisGateOS sends "Authorization: <token>" with no scheme.
    assert auth.presented({'Authorization': TOKEN}) is not None
    assert auth.presented({'Authorization': 'x' * 44}) is None


@pytest.mark.parametrize('bearer', ['x' * 40, 'bsg_short', TOKEN + '!', 'acme_' + 'a' * 40])
def test_wrong_shaped_bearer_is_nothing(bearer):
    assert auth.presented({'Authorization': f'Bearer {bearer}'}) is None


def test_prefix_is_configurable():
    token = 'acme_' + 'a' * 40
    assert auth.presented({'Authorization': f'Bearer {token}'}, prefix='acme_') is not None


def test_certificate_wins_over_token():
    der = b'\x30\x03\x02\x01\x01'
    got = auth.presented({'Authorization': f'Bearer {TOKEN}'}, peer_der=der)
    assert got == {'certFingerprint': hashlib.sha256(der).hexdigest()}


def test_forwarded_certificate_only_when_trusted():
    der = b'\x30\x03\x02\x01\x01'
    headers = {auth.FORWARDED_CERT: base64.b64encode(der).decode()}
    assert auth.presented(headers) is None
    assert auth.presented(headers, trust_forwarded=True) == {
        'certFingerprint': hashlib.sha256(der).hexdigest()}
    # Older Traefik URL-escaped it; a chain is comma-separated, leaf first.
    escaped = base64.b64encode(der).decode().replace('=', '%3D').replace('+', '%2B')
    assert auth.forwarded_der(escaped + ',MIIB') == der
    assert auth.forwarded_der('not base64!') is None
    assert auth.forwarded_der(base64.b64encode(b'\x04abc').decode()) is None
