"""Protected Streamable HTTP endpoint for Railway.

Legacy MCP_AUTH_TOKEN remains supported. Optional Auth0-issued RS256 access
tokens are verified by issuer, audience and signature using the provider JWKS.
OAuth client registration and authorization-code/PKCE happen at Auth0, not here.
"""
import asyncio
import hmac
import json
import logging
import os
import uuid
from urllib.parse import urlsplit

import jwt
from jwt import PyJWKClient
import uvicorn
from starlette.routing import Mount, Route

logger = logging.getLogger("uvicorn.error")


class _ASGIEndpoint:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        await self.app(scope, receive, send)


def mcp_http_app(mcp):
    """Serve the advertised MCP path directly with the pinned MCP 1.9.2 SDK.

    That SDK mounts the handler at /mcp, which redirects /mcp to /mcp/.
    An exact ASGI route avoids redirects while retaining the SDK lifespan.
    """
    app = mcp.streamable_http_app()
    path = mcp.settings.streamable_http_path
    for index, route in enumerate(app.router.routes):
        if isinstance(route, Mount) and route.path == path:
            endpoint = _ASGIEndpoint(route.app)
            app.router.routes[index:index + 1] = [
                Route(path, endpoint=endpoint),
                Route(path.rstrip('/') + '/', endpoint=endpoint),
            ]
            break
    return app


def _json_response(status, payload, extra_headers=()):
    body = json.dumps(payload).encode("utf-8")
    headers = [(b"content-type", b"application/json"), (b"cache-control", b"no-store"), *extra_headers]

    async def respond(send):
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    return respond


def protected_http(app, legacy_token, issuer="", audience="", resource=""):
    issuer = issuer.rstrip("/") + "/" if issuer else ""
    if bool(issuer) != bool(audience):
        raise ValueError("AUTH0_ISSUER and AUTH0_AUDIENCE must both be set or both unset")
    if issuer and not issuer.startswith("https://"):
        raise ValueError("AUTH0_ISSUER must use HTTPS")
    if issuer and (not resource.startswith("https://") or not resource.endswith("/mcp")):
        raise ValueError("MCP_PUBLIC_URL must be an HTTPS URL ending in /mcp")
    jwks = PyJWKClient(issuer + ".well-known/jwks.json", cache_jwk_set=True, lifespan=300) if issuer else None
    resource_path = urlsplit(resource).path if resource else "/mcp"
    metadata_path = "/.well-known/oauth-protected-resource"
    metadata_paths = {metadata_path, metadata_path + resource_path}

    async def guarded(scope, receive, send):
        if scope["type"] != "http":
            await app(scope, receive, send)
            return
        path = scope.get("path", "")
        if issuer and path in metadata_paths and scope.get("method") == "GET":
            await _json_response(200, {
                "resource": resource,
                "authorization_servers": [issuer.rstrip("/")],
                "bearer_methods_supported": ["header"],
            })(send)
            return
        authorization = dict(scope.get("headers", [])).get(b"authorization", b"")
        valid = hmac.compare_digest(authorization, ("Bearer " + legacy_token).encode())
        auth_result = "legacy_ok" if valid else "missing_or_unsupported_authorization"
        if not valid and issuer and authorization.startswith(b"Bearer "):
            try:
                raw = authorization[7:].decode("ascii")
                signing_key = await asyncio.to_thread(jwks.get_signing_key_from_jwt, raw)
                await asyncio.to_thread(
                    jwt.decode, raw, signing_key.key,
                    algorithms=["RS256"], audience=audience, issuer=issuer,
                    options={"require": ["exp", "iss", "aud"]},
                )
                valid = True
                auth_result = "oauth_ok"
            except (jwt.PyJWTError, ValueError, UnicodeError) as exc:
                valid = False
                auth_result = type(exc).__name__
            except Exception as exc:
                # Fail closed if Auth0 JWKS cannot be reached.
                valid = False
                auth_result = type(exc).__name__
        if not valid:
            logger.info("MCP_DIAG auth=%s status=401", auth_result)
            headers = []
            if issuer:
                headers.append((b"www-authenticate", ('Bearer resource_metadata="' + resource.rsplit("/mcp", 1)[0] + metadata_path + '"').encode()))
            await _json_response(401, {"error": "unauthorized"}, headers)(send)
            return
        request_id = uuid.uuid4().hex[:8]
        body = bytearray()
        rpc_method = "unknown"

        async def diagnostic_receive():
            nonlocal rpc_method
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                if len(body) <= 8192:
                    body.extend(chunk[:8193 - len(body)])
                if not message.get("more_body", False) and len(body) <= 8192:
                    try:
                        payload = json.loads(body)
                        method = payload.get("method") if isinstance(payload, dict) else None
                        if method in {"initialize", "notifications/initialized", "tools/list", "tools/call", "ping", "resources/list", "prompts/list"}:
                            rpc_method = method
                    except (ValueError, UnicodeError):
                        pass
            return message

        async def diagnostic_send(message):
            if message["type"] == "http.response.start":
                logger.info("MCP_DIAG id=%s auth=%s rpc=%s status=%s", request_id, auth_result, rpc_method, message["status"])
            await send(message)

        await app(scope, diagnostic_receive, diagnostic_send)

    return guarded


def run_http(mcp):
    token = os.getenv("MCP_AUTH_TOKEN", "")
    if len(token) < 16:
        raise SystemExit("HTTP mode requires MCP_AUTH_TOKEN of at least 16 characters")
    issuer = os.getenv("AUTH0_ISSUER", "")
    audience = os.getenv("AUTH0_AUDIENCE", "")
    resource = os.getenv("MCP_PUBLIC_URL", "")
    if issuer and not resource:
        raise SystemExit("MCP_PUBLIC_URL is required when AUTH0_ISSUER is set")
    app = protected_http(mcp_http_app(mcp), token, issuer, audience, resource)
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
