"""Passkeys (WebAuthn) using Yubico's fido2 library (Debian python3-fido2).

Ceremony state (the challenge) is held server-side in memory for a few minutes, keyed by a
random handle the browser carries in a short-lived cookie. Attestation is "none": a home app
has no reason to restrict which authenticator brands may be used.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

import fido2.features

# Make fido2's dict() / from_dict() use the WebAuthn JSON format (base64url strings) that
# browsers send and expect. This is the default from fido2 2.0 onward.
if not fido2.features.webauthn_json_mapping._enabled:
    fido2.features.webauthn_json_mapping.enabled = True

from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticationResponse,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

# Long enough for the sign-in page's background (autofill) request to sit while someone types.
STATE_TTL_S = 600
# Pending ceremonies kept at once; beyond this the oldest are dropped (never all of them, so a
# flood of begin requests can't cancel someone's sign-in that is already in progress).
MAX_STATES = 1000


@dataclass(frozen=True)
class NewPasskey:
    credential_id: bytes
    credential_data: bytes  # AttestedCredentialData (AAGUID + id + COSE public key)
    sign_count: int


@dataclass(frozen=True)
class Assertion:
    credential_id: bytes
    user_handle: bytes | None
    sign_count: int


class PasskeyError(Exception):
    pass


class UnknownPasskey(PasskeyError):
    """The browser offered a passkey this doorman has no record of (deleted, or from another
    install that used the same site name). The browser can be told to stop offering it."""

    def __init__(self, credential_id: bytes) -> None:
        super().__init__(
            "This passkey isn't registered with doorman. Your password manager may be offering an "
            "old one for this site: delete it there, or sign in with your password and add a new one."
        )
        self.credential_id = credential_id


def user_handle(user_id: int) -> bytes:
    return f"doorman-user-{user_id}".encode()


def user_id_from_handle(handle: bytes | None) -> int | None:
    if not handle or not handle.startswith(b"doorman-user-"):
        return None
    try:
        return int(handle.removeprefix(b"doorman-user-"))
    except ValueError:
        return None


def _auth_kind(require_uv: bool) -> str:
    return "auth-uv" if require_uv else "auth-2fa"


class Passkeys:
    def __init__(self, rp_id: str, rp_name: str, origin: str) -> None:
        self.rp_id = rp_id
        self.origin = origin
        self.server = Fido2Server(
            PublicKeyCredentialRpEntity(id=rp_id, name=rp_name),
            verify_origin=lambda o: o == origin,
        )
        self._states: dict[str, tuple[float, str, Any]] = {}
        self._lock = threading.Lock()

    # -- state ----------------------------------------------------------------------------------

    def _put(self, kind: str, state: Any) -> str:
        handle = secrets.token_urlsafe(24)
        now = time.monotonic()
        with self._lock:
            self._states = {k: v for k, v in self._states.items() if now - v[0] < STATE_TTL_S}
            while len(self._states) >= MAX_STATES:
                del self._states[next(iter(self._states))]  # dicts keep insertion order: oldest first
            self._states[handle] = (now, kind, state)
        return handle

    def _take(self, handle: str, kind: str) -> Any:
        with self._lock:
            entry = self._states.pop(handle, None)
        if entry is None or entry[1] != kind or time.monotonic() - entry[0] > STATE_TTL_S:
            raise PasskeyError("That passkey request expired. Try again.")
        return entry[2]

    # -- registration ---------------------------------------------------------------------------

    def begin_registration(
        self, user_id: int, username: str, display_name: str, existing: list[bytes]
    ) -> tuple[str, dict[str, Any]]:
        options, state = self.server.register_begin(
            PublicKeyCredentialUserEntity(
                id=user_handle(user_id), name=username, display_name=display_name or username
            ),
            credentials=[AttestedCredentialData(c) for c in existing],
            resident_key_requirement=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        return self._put(f"reg:{user_id}", state), dict(options)

    def finish_registration(self, handle: str, response: dict[str, Any], user_id: int) -> NewPasskey:
        # The handle only completes for the account that started it.
        state = self._take(handle, f"reg:{user_id}")
        try:
            auth_data = self.server.register_complete(state, response)
        except Exception as e:  # fido2 raises ValueError/KeyError/etc. on bad input
            raise PasskeyError(f"The passkey couldn't be verified ({e}).") from e
        cred = auth_data.credential_data
        if cred is None:
            raise PasskeyError("The authenticator didn't return a credential.")
        return NewPasskey(bytes(cred.credential_id), bytes(cred), auth_data.counter)

    # -- Signal API payloads ----------------------------------------------------------------------
    # Browsers and password managers that support the WebAuthn Signal API use these to hide
    # passkeys the server no longer accepts, so stale ones stop being offered at sign-in.

    def signal_unknown(self, credential_id: bytes) -> dict[str, str]:
        return {"rpId": self.rp_id, "credentialId": websafe_encode(credential_id)}

    def signal_accepted(self, user_id: int, credential_ids: list[bytes]) -> dict[str, Any]:
        return {
            "rpId": self.rp_id,
            "userId": websafe_encode(user_handle(user_id)),
            "allAcceptedCredentialIds": [websafe_encode(c) for c in credential_ids],
        }

    # -- authentication -------------------------------------------------------------------------

    def begin_authentication(
        self, allowed: list[bytes] | None = None, *, require_uv: bool = True
    ) -> tuple[str, dict[str, Any]]:
        """``allowed`` = stored credential_data blobs; None lets any discoverable passkey answer.

        ``require_uv``: the authenticator must verify the person (PIN, fingerprint, face). Required
        whenever the passkey is the whole sign-in (passwordless, re-auth); a passkey that is only
        the second step after a password may skip it. The two kinds of request get different
        handles, so one can't be finished as the other.
        """
        creds = [AttestedCredentialData(c) for c in allowed] if allowed else None
        uv = UserVerificationRequirement.REQUIRED if require_uv else UserVerificationRequirement.PREFERRED
        options, state = self.server.authenticate_begin(credentials=creds, user_verification=uv)
        return self._put(_auth_kind(require_uv), state), dict(options)

    @staticmethod
    def credential_id_of(response: dict[str, Any]) -> bytes:
        try:
            return websafe_decode(response["rawId"])
        except Exception as e:
            raise PasskeyError("Malformed passkey response.") from e

    def finish_authentication(
        self,
        handle: str,
        response: dict[str, Any],
        credential_data: bytes,
        stored_sign_count: int,
        *,
        require_uv: bool = True,
    ) -> Assertion:
        state = self._take(handle, _auth_kind(require_uv))
        try:
            parsed = AuthenticationResponse.from_dict(response)
            self.server.authenticate_complete(state, [AttestedCredentialData(credential_data)], response)
        except Exception as e:
            raise PasskeyError(f"The passkey couldn't be verified ({e}).") from e
        counter = parsed.response.authenticator_data.counter
        # Counters only increase on authenticators that implement them (synced passkeys send 0).
        if counter and stored_sign_count and counter <= stored_sign_count:
            raise PasskeyError("This passkey's counter went backwards; it may have been cloned.")
        return Assertion(bytes(parsed.id), parsed.response.user_handle, counter)
