"""Unit tests for Auth0 resource authentication wrapper (no network calls)."""
import asyncio
import json
import unittest
from unittest.mock import patch

from src.http_server import protected_http


class AuthTests(unittest.TestCase):
    def test_rejects_incomplete_configuration(self):
        with self.assertRaises(ValueError):
            protected_http(lambda *_: None, "x" * 20, issuer="https://example.auth0.com/")

    def test_legacy_token_and_metadata(self):
        calls = []

        async def downstream(scope, receive, send):
            calls.append(scope["path"])
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        async def invoke(path, authorization=None):
            sent = []
            headers = [(b"authorization", authorization.encode())] if authorization else []
            scope = {"type": "http", "path": path, "method": "GET", "headers": headers}
            async def send(message):
                sent.append(message)
            await app(scope, lambda: None, send)
            return sent

        with patch("src.http_server.PyJWKClient"):
            app = protected_http(
                downstream, "a" * 20,
                "https://example.auth0.com/", "https://example.test/api",
                "https://mcp.example.com/mcp",
            )
            response = asyncio.run(invoke("/.well-known/oauth-protected-resource"))
            self.assertEqual(response[0]["status"], 200)
            metadata = json.loads(response[1]["body"])
            self.assertEqual(metadata["resource"], "https://mcp.example.com/mcp")
            response = asyncio.run(invoke("/mcp"))
            self.assertEqual(response[0]["status"], 401)
            response = asyncio.run(invoke("/mcp", "Bearer " + "a" * 20))
            self.assertEqual(response[0]["status"], 200)
            self.assertEqual(calls, ["/mcp"])


if __name__ == "__main__":
    unittest.main()
