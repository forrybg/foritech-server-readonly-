import base64
import hashlib
import http.client
import importlib.util
import json
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit


MODULE_PATH = Path(__file__).parents[1] / "server.py"
SPEC = importlib.util.spec_from_file_location("foritech_server_readonly", MODULE_PATH)
server_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server_module)


CLIENT_ID = "https://chatgpt.com/oauth/foritech-server/client.json"
REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect"
PREDEFINED_CLIENT_ID = "aa11bb22cc33dd44ee55ff66.access"
PREDEFINED_REDIRECT_URI = "https://chatgpt.com/connector/oauth/test-fixture-only"
VERIFIER = "b" * 64
CHALLENGE = base64.urlsafe_b64encode(
    hashlib.sha256(VERIFIER.encode("ascii")).digest()
).rstrip(b"=").decode("ascii")
TEST_PASSWORD = "correct-test-password"
TEST_SALT = b"foritech-server-test-salt"
TEST_ITERATIONS = 200_000
TEST_DIGEST = hashlib.pbkdf2_hmac(
    "sha256", TEST_PASSWORD.encode("utf-8"), TEST_SALT, TEST_ITERATIONS
)
TEST_PASSWORD_HASH = "pbkdf2_sha256${}${}${}".format(
    TEST_ITERATIONS,
    base64.urlsafe_b64encode(TEST_SALT).decode("ascii"),
    base64.urlsafe_b64encode(TEST_DIGEST).decode("ascii"),
)


class ServerReadonlyOAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server_module.HTTPServer(("127.0.0.1", 0), server_module.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        with server_module._oauth_lock:
            server_module._authorization_codes.clear()
            server_module._access_tokens.clear()
        self.auth_token_patch = patch.object(server_module, "AUTH_TOKEN", "manual-test-token")
        self.password_hash_patch = patch.object(
            server_module, "LOGIN_PASSWORD_HASH", TEST_PASSWORD_HASH
        )
        self.client_id_patch = patch.object(server_module, "PREDEFINED_CLIENT_ID", PREDEFINED_CLIENT_ID)
        self.redirect_patch = patch.object(server_module, "PREDEFINED_REDIRECT_URI", PREDEFINED_REDIRECT_URI)
        self.auth_token_patch.start()
        self.password_hash_patch.start()
        self.client_id_patch.start()
        self.redirect_patch.start()

    def tearDown(self):
        self.auth_token_patch.stop()
        self.password_hash_patch.stop()
        self.client_id_patch.stop()
        self.redirect_patch.stop()

    def json_request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            raw = resp.read()
            payload = None
            if raw:
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError:
                    payload = raw.decode("utf-8", errors="replace")
            return resp.status, dict(resp.getheaders()), payload
        finally:
            conn.close()

    def initialize(self, token):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        return self.json_request(
            "POST",
            "/server/mcp",
            body=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        )

    def authorize_with_pkce(self, use_predefined=False):
        client_id = PREDEFINED_CLIENT_ID if use_predefined else CLIENT_ID
        redirect_uri = PREDEFINED_REDIRECT_URI if use_predefined else REDIRECT_URI
        query = urlencode({
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "resource": server_module.RESOURCE,
            "scope": server_module.SCOPE,
            "state": "state-abc",
        })
        body = urlencode({"password": TEST_PASSWORD})

        # Non-predefined clients go through Client ID Metadata Document
        # (CIMD) discovery, which normally fetches client_id over HTTPS.
        # That real network call depends on an actual registered ChatGPT
        # connector and is not something a unit test should depend on, so
        # it is mocked here to return a metadata document that trusts our
        # own REDIRECT_URI fixture.
        if use_predefined:
            status, headers, _ = self.json_request(
                "POST",
                f"/server/authorize?{query}",
                body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        else:
            with patch.object(
                server_module, "fetch_client_metadata",
                return_value={"client_id": client_id, "redirect_uris": [redirect_uri]},
            ):
                status, headers, _ = self.json_request(
                    "POST",
                    f"/server/authorize?{query}",
                    body=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
        self.assertEqual(status, 302)
        location = headers["Location"]
        code = parse_qs(urlsplit(location).query)["code"][0]
        return client_id, redirect_uri, code

    def exchange_token(self, client_id, redirect_uri, code, verifier=VERIFIER):
        body = urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "resource": server_module.RESOURCE,
            "code_verifier": verifier,
        })
        return self.json_request(
            "POST", "/server/token", body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def issue_token(self):
        client_id, redirect_uri, code = self.authorize_with_pkce()
        status, _, payload = self.exchange_token(client_id, redirect_uri, code)
        self.assertEqual(status, 200)
        return payload["access_token"]

    def test_routes_are_under_server_prefix(self):
        status, _, payload = self.json_request("GET", "/server/.well-known/oauth-protected-resource")
        self.assertEqual(status, 200)
        self.assertEqual(payload["resource"], "https://mcp-readonly.foritech.bg/server")

        status, _, payload = self.json_request("GET", "/server/.well-known/oauth-authorization-server")
        self.assertEqual(status, 200)
        self.assertEqual(payload["authorization_endpoint"], "https://mcp-readonly.foritech.bg/server/authorize")
        self.assertEqual(payload["token_endpoint"], "https://mcp-readonly.foritech.bg/server/token")

    def test_unprefixed_legacy_routes_are_not_served(self):
        # This service must never answer on the bare Diagnostics-3-style
        # paths; it only understands its own /server-prefixed routes.
        status, _, _ = self.json_request("GET", "/.well-known/oauth-protected-resource")
        self.assertEqual(status, 405)
        status, _, payload = self.json_request(
            "POST", "/mcp", body="{}", headers={"Content-Type": "application/json"}
        )
        self.assertEqual(status, 404)

    def test_missing_bearer_has_oauth_challenge(self):
        status, headers, payload = self.json_request(
            "POST", "/server/mcp", body="{}", headers={"Content-Type": "application/json"}
        )
        self.assertEqual(status, 401)
        self.assertIn("WWW-Authenticate", headers)
        self.assertIn("/server/.well-known/oauth-protected-resource/mcp", headers["WWW-Authenticate"])

    def test_invalid_bearer_rejected(self):
        status, _, _ = self.initialize("not-a-real-token")
        self.assertEqual(status, 401)

    def test_manual_token_permits_initialize(self):
        status, _, payload = self.initialize("manual-test-token")
        self.assertEqual(status, 200)
        self.assertEqual(payload["result"]["serverInfo"]["name"], "foritech-server-readonly")

    def test_missing_pkce_is_rejected(self):
        query = urlencode({
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": "",
            "code_challenge_method": "S256",
            "resource": server_module.RESOURCE,
            "scope": server_module.SCOPE,
            "state": "state-123",
        })
        body = urlencode({"password": TEST_PASSWORD})
        status, _, _ = self.json_request(
            "POST", f"/server/authorize?{query}", body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 400)

    def test_valid_pkce_flow_and_code_replay_rejection(self):
        client_id, redirect_uri, code = self.authorize_with_pkce()
        status, _, payload = self.exchange_token(client_id, redirect_uri, code)
        self.assertEqual(status, 200)
        self.assertEqual(payload["token_type"], "Bearer")
        self.assertEqual(payload["scope"], "mcp:read")

        # replay must fail: the code was single-use
        status2, _, _ = self.exchange_token(client_id, redirect_uri, code)
        self.assertEqual(status2, 400)

    def test_wrong_verifier_is_rejected(self):
        client_id, redirect_uri, code = self.authorize_with_pkce()
        status, _, payload = self.exchange_token(client_id, redirect_uri, code, verifier="wrong-verifier")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "invalid_grant")

    def test_redirect_uri_mismatch_is_rejected(self):
        client_id, redirect_uri, code = self.authorize_with_pkce()
        status, _, payload = self.exchange_token(client_id, "https://chatgpt.com/wrong/path", code)
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "invalid_grant")
        self.assertEqual(payload["reason"], "REDIRECT_URI_MISMATCH")

    def test_predefined_client_requires_exact_redirect(self):
        query = urlencode({
            "response_type": "code",
            "client_id": PREDEFINED_CLIENT_ID,
            "redirect_uri": "https://chatgpt.com/connector/oauth/not-the-configured-app",
            "resource": server_module.RESOURCE,
        })
        body = urlencode({"password": TEST_PASSWORD})
        status, _, _ = self.json_request(
            "POST", f"/server/authorize?{query}", body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 400)

    def test_expired_token_is_rejected(self):
        token = self.issue_token()
        with server_module._oauth_lock:
            server_module._access_tokens[server_module._secret_key(token)]["expires_at"] = 0
        status, _, _ = self.initialize(token)
        self.assertEqual(status, 401)

    def test_tool_allowlist_matches_policy_and_server(self):
        listed = {tool["name"] for tool in server_module.mcp_tools_list()["tools"]}
        self.assertEqual(listed, server_module.ALLOWED_TOOLS)
        self.assertEqual(set(server_module.TOOLS.keys()), server_module.ALLOWED_TOOLS)

    def test_no_write_or_shell_tool_is_reachable(self):
        body = json.dumps({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "run_command", "arguments": {}},
        })
        status, _, payload = self.json_request(
            "POST", "/server/mcp", body=body,
            headers={"Content-Type": "application/json", "Authorization": "Bearer manual-test-token"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["result"]["isError"])
        content = json.loads(payload["result"]["content"][0]["text"])
        self.assertEqual(content["status"], "REJECTED_BY_POLICY")


if __name__ == "__main__":
    unittest.main()
