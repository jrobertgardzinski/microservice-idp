"""The stub IdP honours the Authorization Code + PKCE contract it advertises."""

import base64
import hashlib
import hmac
import json
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

from server import (CLIENT_ID, CLIENT_SECRET, CODE_TTL_SECONDS, ISSUER, Handler, REDIRECT_URIS,
                    _codes, b64url, exchange, issue_code, subject_of, userinfo)


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


class BoundaryTest(unittest.TestCase):
    """The HTTP edge, where the header-splitting and the unbounded growth actually lived.

    These drive a real server on a real socket rather than calling the functions: the defects being
    guarded here were in what reached `send_header` and in what the handler did with a malformed
    request line — neither is visible from the pure functions above.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def authorize(self, redirect_uri, email="carol@example.com"):
        query = urlencode({"client_id": CLIENT_ID, "redirect_uri": redirect_uri, "state": "s",
                           "nonce": "n", "code_challenge": challenge_of("v"), "email": email})
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request("GET", "/authorize?" + query)
        response = connection.getresponse()
        response.read()
        connection.close()
        return response

    def test_an_unregistered_redirect_uri_is_refused(self):
        # an open redirect on its own, and the carrier for the header split below
        self.assertEqual(400, self.authorize("http://evil.example/cb").status)

    def test_a_redirect_uri_carrying_crlf_cannot_split_the_response(self):
        # the payload: a newline inside redirect_uri used to end the Location header and let the
        # caller write their own. Set-Cookie is the prize — cookies ignore ports, so one planted
        # from this service applies to security on :8080 as well.
        split = REDIRECT_URIS[0] + "\r\nSet-Cookie: pwned=1"
        response = self.authorize(split)

        self.assertEqual(400, response.status)
        self.assertIsNone(response.getheader("Set-Cookie"),
                          "no header may appear that this service did not write itself")

    def test_a_registered_redirect_uri_still_works(self):
        response = self.authorize(REDIRECT_URIS[0])

        self.assertEqual(302, response.status)
        self.assertTrue(response.getheader("Location").startswith(REDIRECT_URIS[0] + "?code="))

    def test_a_bogus_content_length_answers_400_instead_of_dropping_the_connection(self):
        # security cannot tell a dropped connection apart from a dead provider; it can read a 400
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.putrequest("POST", "/token")
        connection.putheader("Content-Length", "not-a-number")
        connection.endheaders()
        response = connection.getresponse()
        response.read()

        self.assertEqual(400, response.status)

    def test_expired_codes_do_not_accumulate(self):
        # /authorize is unauthenticated, so a code nobody exchanges used to be a permanent
        # allocation any caller could drive — with a 128Mi limit and a liveness probe behind it
        _codes.clear()
        issue_code("old@example.com", "n", challenge_of("v"), REDIRECT_URIS[0], now=1_000)
        self.assertEqual(1, len(_codes))

        issue_code("new@example.com", "n", challenge_of("v"), REDIRECT_URIS[0],
                   now=1_000 + CODE_TTL_SECONDS + 1)

        self.assertEqual(1, len(_codes), "the abandoned code is swept when the next one is issued")
        self.assertEqual("new@example.com", next(iter(_codes.values()))["email"])
