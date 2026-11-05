"""Identity assurance: a correctly recognised face is not a permission.

Authentication answers "who is this". Authorization answers "may this identity do this". Systems
fail when the first is treated as the second, and the failure is invisible in a log that only
records successful logins.

This module models the distinction so the tests can hold it still: every attempt records both
answers, and an authenticated attempt that is refused is a *finding*, not a quiet success.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field

#: role -> the actions it may perform. Deliberately small and explicit.
POLICY: dict[str, set[str]] = {
    "guard": {"door:open", "log:read"},
    "restorer": {"case:read", "case:photograph"},
    "curator": {"case:read", "case:open", "vault:open"},
    "auditor": {"log:read"},
}


@dataclass(frozen=True)
class Credential:
    subject: str
    role: str
    issued: float
    expires: float
    nonce: str
    device: str
    signature: str = ""


@dataclass
class Attempt:
    subject: str
    action: str
    authenticated: bool
    authorized: bool
    reason: str
    at: float


def sign(cred: Credential, secret: bytes) -> str:
    body = f"{cred.subject}|{cred.role}|{cred.issued}|{cred.expires}|{cred.nonce}|{cred.device}"
    return hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()


def issue(subject: str, role: str, secret: bytes, *, ttl: float = 3600.0,
          device: str = "reader-1", now: float | None = None) -> Credential:
    at = time.time() if now is None else now
    cred = Credential(subject, role, at, at + ttl, f"{subject}-{int(at)}", device)
    return Credential(**{**cred.__dict__, "signature": sign(cred, secret)})


def authenticate(cred: Credential, secret: bytes, *, now: float | None = None,
                 seen_nonces: set[str] | None = None,
                 device_present: str | None = None) -> tuple[bool, str]:
    """Who is this. Nothing about permission is decided here."""
    at = time.time() if now is None else now
    if not hmac.compare_digest(cred.signature, sign(cred, secret)):
        return False, "signature does not verify"
    if at > cred.expires:
        return False, "credential expired"
    if at < cred.issued - 60:
        return False, "credential issued in the future"
    if seen_nonces is not None and cred.nonce in seen_nonces:
        return False, "nonce replayed"
    if device_present is not None and device_present != cred.device:
        return False, f"presented from {device_present}, bound to {cred.device}"
    return True, "authenticated"


def authorize(role: str, action: str) -> tuple[bool, str]:
    allowed = POLICY.get(role, set())
    if action in allowed:
        return True, f"role {role} may {action}"
    return False, f"role {role} may not {action}"


def attempt(cred: Credential, action: str, secret: bytes, *, log: list[Attempt] | None = None,
            now: float | None = None, seen_nonces: set[str] | None = None,
            device_present: str | None = None) -> Attempt:
    """Authenticate, then authorize, then record both answers. Order matters: a refusal is
    recorded as a refusal, not as nothing."""
    ok_auth, why = authenticate(cred, secret, now=now, seen_nonces=seen_nonces,
                                device_present=device_present)
    ok_authz = False
    if ok_auth:
        ok_authz, why = authorize(cred.role, action)
        if seen_nonces is not None:
            seen_nonces.add(cred.nonce)
    record = Attempt(cred.subject, action, ok_auth, ok_authz, why,
                     time.time() if now is None else now)
    if log is not None:
        log.append(record)
    return record


def audit_gaps(log: list[Attempt], expected_actions: set[str]) -> list[str]:
    """Actions nobody attempted are as interesting as actions that failed: a deleted log entry
    and an action that never happened look identical from inside the file."""
    seen = {a.action for a in log}
    return sorted(expected_actions - seen)
