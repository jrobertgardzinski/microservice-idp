"""The stub IdP honours the Authorization Code + PKCE contract it advertises."""

import base64
import hashlib
import hmac
import json
import unittest

from server import CLIENT_ID, CLIENT_SECRET, ISSUER, b64url, exchange, issue_code, subject_of, userinfo


def challenge_of(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode()).digest())


def decode_segment(segment: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


class StubIdpTest(unittest.TestCase):

    def test_the_full_code_exchange_yields_a_verifiable_id_token(self):
        code = issue_code("alice@example.com", "nonce-1", challenge_of("ver-1"), "https://app/cb")
        tokens = exchange(code, "ver-1", CLIENT_ID, CLIENT_SECRET, "https://app/cb")

        header, claims, signature = tokens["id_token"].split(".")
        self.assertEqual("HS256", decode_segment(header)["alg"])
        body = decode_segment(claims)
        self.assertEqual(ISSUER, body["iss"])
        self.assertEqual(CLIENT_ID, body["aud"])
        self.assertEqual("alice@example.com", body["email"])
        self.assertTrue(body["email_verified"])
        self.assertEqual("nonce-1", body["nonce"])
        self.assertEqual(subject_of("alice@example.com"), body["sub"])
        expected = hmac.new(CLIENT_SECRET.encode(), f"{header}.{claims}".encode(), hashlib.sha256).digest()
        self.assertEqual(b64url(expected), signature, "the id_token verifies with the client secret")

    def test_the_access_token_reads_userinfo(self):
        code = issue_code("bob@example.com", "n", challenge_of("v"), "https://app/cb")
        tokens = exchange(code, "v", CLIENT_ID, CLIENT_SECRET, "https://app/cb")
        info = userinfo(tokens["access_token"])
        self.assertEqual({"sub": subject_of("bob@example.com"), "email": "bob@example.com",
                          "email_verified": True}, info)

    def test_a_code_is_single_use(self):
        code = issue_code("carol@example.com", "n", challenge_of("v"), "https://app/cb")
        exchange(code, "v", CLIENT_ID, CLIENT_SECRET, "https://app/cb")
        with self.assertRaises(ValueError):
            exchange(code, "v", CLIENT_ID, CLIENT_SECRET, "https://app/cb")

    def test_a_wrong_pkce_verifier_or_client_secret_or_redirect_is_refused(self):
        for verifier, secret, redirect in (
                ("WRONG", CLIENT_SECRET, "https://app/cb"),
                ("v", "WRONG", "https://app/cb"),
                ("v", CLIENT_SECRET, "https://evil/cb")):
            code = issue_code("dave@example.com", "n", challenge_of("v"), "https://app/cb")
            with self.assertRaises(ValueError):
                exchange(code, verifier, CLIENT_ID, secret, redirect)

    def test_an_expired_code_is_refused(self):
        code = issue_code("erin@example.com", "n", challenge_of("v"), "https://app/cb", now=1000)
        with self.assertRaises(ValueError):
            exchange(code, "v", CLIENT_ID, CLIENT_SECRET, "https://app/cb", now=1000 + 301)


if __name__ == "__main__":
    unittest.main()
