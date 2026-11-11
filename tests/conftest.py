import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from basicstation_gate import signer


@pytest.fixture
def keys(tmp_path, monkeypatch):
    """Development keys plus a signing key, as the signer loads them."""
    path = tmp_path / 'signing.pem'
    path.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    for name in ('CLIENT_CA_KEY_FILE', 'CLIENT_CA_CERT_FILE', 'CUPS_TRUST_FILE', 'TC_TRUST_FILE'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('DEV_STATE_DIR', str(tmp_path / 'dev'))
    monkeypatch.setenv('SIGNING_KEY_FILE', str(path))
    return signer.Keys.from_env()


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    """Run `async def` tests without a plugin."""
    import asyncio
    import inspect

    if inspect.iscoroutinefunction(pyfuncitem.obj):
        names = pyfuncitem._fixtureinfo.argnames
        asyncio.run(pyfuncitem.obj(**{n: pyfuncitem.funcargs[n] for n in names}))
        return True
    return None
