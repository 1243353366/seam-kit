"""Authentication and authorization are two questions, and the tests keep them apart."""
from __future__ import annotations

import unittest

from lab import identity as idn

SECRET = b"test-secret-for-identity-assurance"
NOW = 1_800_000_000.0


class AuthenticationTests(unittest.TestCase):
    def test_a_valid_credential_authenticates(self):
        cred = idn.issue("ada", "guard", SECRET, now=NOW)
        ok, why = idn.authenticate(cred, SECRET, now=NOW + 10)
        self.assertTrue(ok, why)

    def test_a_tampered_role_breaks_the_signature(self):
        cred = idn.issue("ada", "guard", SECRET, now=NOW)
        forged = idn.Credential(cred.subject, "curator", cred.issued, cred.expires,
                                cred.nonce, cred.device, cred.signature)
        ok, why = idn.authenticate(forged, SECRET, now=NOW + 10)
        self.assertFalse(ok)
        self.assertIn("signature", why)

    def test_expiry_is_checked_before_permission(self):
        cred = idn.issue("ada", "guard", SECRET, ttl=60, now=NOW)
        ok, why = idn.authenticate(cred, SECRET, now=NOW + 61)
        self.assertFalse(ok)
        self.assertIn("expired", why)

    def test_a_replayed_nonce_is_refused(self):
        cred = idn.issue("ada", "guard", SECRET, now=NOW)
        seen = {cred.nonce}
        ok, why = idn.authenticate(cred, SECRET, now=NOW + 5, seen_nonces=seen)
        self.assertFalse(ok)
        self.assertIn("replay", why)

    def test_a_stolen_credential_on_another_device_is_refused(self):
        cred = idn.issue("ada", "guard", SECRET, now=NOW, device="reader-1")
        ok, why = idn.authenticate(cred, SECRET, now=NOW + 5, device_present="reader-9")
        self.assertFalse(ok)
        self.assertIn("reader-9", why)


class AuthorizationTests(unittest.TestCase):
    def test_a_recognised_person_can_still_be_refused(self):
        """The bug this module exists for: identity verified, permission absent."""
        cred = idn.issue("ada", "restorer", SECRET, now=NOW)
        record = idn.attempt(cred, "vault:open", SECRET, now=NOW + 1)
        self.assertTrue(record.authenticated, "she is who she says she is")
        self.assertFalse(record.authorized, "and she still may not open the vault")
        self.assertIn("may not", record.reason)

    def test_an_allowed_action_is_allowed(self):
        cred = idn.issue("ada", "curator", SECRET, now=NOW)
        record = idn.attempt(cred, "vault:open", SECRET, now=NOW + 1)
        self.assertTrue(record.authenticated)
        self.assertTrue(record.authorized)

    def test_an_unknown_role_gets_nothing(self):
        ok, _ = idn.authorize("intern", "case:read")
        self.assertFalse(ok)

    def test_a_failed_authentication_never_reaches_authorization(self):
        cred = idn.issue("ada", "guard", SECRET, now=NOW)
        record = idn.attempt(cred, "door:open", b"wrong-secret", now=NOW + 1)
        self.assertFalse(record.authenticated)
        self.assertFalse(record.authorized)


class AuditTests(unittest.TestCase):
    def test_every_attempt_is_recorded_including_refusals(self):
        log = []
        good = idn.issue("ada", "guard", SECRET, now=NOW)
        idn.attempt(good, "door:open", SECRET, log=log, now=NOW + 1)
        idn.attempt(good, "vault:open", SECRET, log=log, now=NOW + 2)
        self.assertEqual(len(log), 2)
        self.assertEqual([a.authorized for a in log], [True, False])

    def test_a_nonce_cannot_be_spent_twice_through_attempt(self):
        seen: set[str] = set()
        cred = idn.issue("ada", "guard", SECRET, now=NOW)
        first = idn.attempt(cred, "door:open", SECRET, now=NOW + 1, seen_nonces=seen,
                            device_present="reader-1")
        second = idn.attempt(cred, "door:open", SECRET, now=NOW + 2, seen_nonces=seen,
                             device_present="reader-1")
        self.assertTrue(first.authorized)
        self.assertFalse(second.authenticated, "the same credential, twice, is a replay")

    def test_missing_actions_are_reported_not_assumed(self):
        log = []
        cred = idn.issue("ada", "guard", SECRET, now=NOW)
        idn.attempt(cred, "door:open", SECRET, log=log, now=NOW + 1)
        gaps = idn.audit_gaps(log, {"door:open", "log:read"})
        self.assertEqual(gaps, ["log:read"])
