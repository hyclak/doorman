"""End-to-end passkey ceremonies against a software authenticator (P-256, 'none' attestation)."""

import hashlib
import json
import os
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.utils import websafe_decode, websafe_encode

from doorman.auth.passkeys import PasskeyError, Passkeys, user_handle, user_id_from_handle

ORIGIN = "https://door.example.org:3667"
RP_ID = "door.example.org"


class SoftAuthenticator:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.counter = 0
        self.handle = None

    def _cose(self):
        n = self.key.public_key().public_numbers()
        return {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}

    def _auth_data(self, rp_id, attested):
        flags = 0x01 | 0x04 | (0x40 if attested else 0)  # UP | UV | AT
        out = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter)
        if attested:
            out += (
                b"\0" * 16 + struct.pack(">H", len(self.cred_id)) + self.cred_id + cbor.encode(self._cose())
            )
        return out

    @staticmethod
    def _client_data(kind, challenge, origin):
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False}
        ).encode()

    def create(self, options, origin=ORIGIN):
        pk = options["publicKey"]
        self.handle = websafe_decode(pk["user"]["id"])
        cd = self._client_data("webauthn.create", pk["challenge"], origin)
        att = cbor.encode({"fmt": "none", "attStmt": {}, "authData": self._auth_data(pk["rp"]["id"], True)})
        return {
            "id": websafe_encode(self.cred_id),
            "rawId": websafe_encode(self.cred_id),
            "type": "public-key",
            "response": {"clientDataJSON": websafe_encode(cd), "attestationObject": websafe_encode(att)},
        }

    def get(self, options, rp_id=RP_ID, origin=ORIGIN):
        pk = options["publicKey"]
        self.counter += 1
        cd = self._client_data("webauthn.get", pk["challenge"], origin)
        ad = self._auth_data(rp_id, False)
        sig = self.key.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": websafe_encode(self.cred_id),
            "rawId": websafe_encode(self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(cd),
                "authenticatorData": websafe_encode(ad),
                "signature": websafe_encode(sig),
                "userHandle": websafe_encode(self.handle),
            },
        }


@pytest.fixture
def pk():
    return Passkeys(RP_ID, "doorman", ORIGIN)


def register(pk, auth):
    handle, options = pk.begin_registration(7, "alice", "Alice", existing=[])
    return pk.finish_registration(handle, auth.create(options))


def test_register_and_authenticate(pk):
    auth = SoftAuthenticator()
    new = register(pk, auth)
    assert new.credential_id == auth.cred_id

    handle, options = pk.begin_authentication()
    resp = auth.get(options)
    assert pk.credential_id_of(resp) == auth.cred_id
    a = pk.finish_authentication(handle, resp, new.credential_data, new.sign_count)
    assert user_id_from_handle(a.user_handle) == 7
    assert a.sign_count == 1


def test_wrong_origin_rejected(pk):
    auth = SoftAuthenticator()
    handle, options = pk.begin_registration(7, "alice", "Alice", existing=[])
    with pytest.raises(PasskeyError):
        pk.finish_registration(handle, auth.create(options, origin="https://evil.example"))


def test_state_is_single_use(pk):
    auth = SoftAuthenticator()
    new = register(pk, auth)
    handle, options = pk.begin_authentication()
    resp = auth.get(options)
    pk.finish_authentication(handle, resp, new.credential_data, 0)
    with pytest.raises(PasskeyError, match="expired"):
        pk.finish_authentication(handle, resp, new.credential_data, 0)


def test_counter_regression_rejected(pk):
    auth = SoftAuthenticator()
    new = register(pk, auth)
    handle, options = pk.begin_authentication()
    with pytest.raises(PasskeyError, match="counter"):
        pk.finish_authentication(handle, auth.get(options), new.credential_data, stored_sign_count=50)


def test_signature_from_other_key_rejected(pk):
    auth = SoftAuthenticator()
    new = register(pk, auth)
    imposter = SoftAuthenticator()
    imposter.cred_id, imposter.handle = auth.cred_id, auth.handle
    handle, options = pk.begin_authentication()
    with pytest.raises(PasskeyError):
        pk.finish_authentication(handle, imposter.get(options), new.credential_data, 0)


def test_user_handle_roundtrip():
    assert user_id_from_handle(user_handle(42)) == 42
    assert user_id_from_handle(b"other") is None


def test_signal_payloads(pk):
    assert pk.signal_unknown(b"\x01\x02") == {"rpId": RP_ID, "credentialId": "AQI"}
    out = pk.signal_accepted(7, [b"\x01\x02"])
    assert out["rpId"] == RP_ID and out["allAcceptedCredentialIds"] == ["AQI"]
    assert user_id_from_handle(websafe_decode(out["userId"])) == 7
