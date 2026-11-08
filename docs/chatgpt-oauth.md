# ChatGPT OAuth integration (draft)

This branch adds **resource-server** support for Auth0-issued RS256 JWT access tokens while preserving the existing `MCP_AUTH_TOKEN` bearer path. It does **not** implement an OAuth authorization server, Dynamic Client Registration, or a Client ID Metadata Document. These must be supplied by a compatible identity provider / configured OAuth client. Do not merge before end-to-end testing.

## Auth0 configuration

1. Create an Auth0 API (resource server). Use a distinct HTTPS identifier as its audience, e.g. `https://facebook-ads-mcp.example.com`.
2. Configure a Regular Web Application with Authorization Code + PKCE. Register the **exact callback URL shown by ChatGPT** for your custom MCP plugin. Confirm that ChatGPT can use the selected client-registration method; if not, this branch alone will not make the connection possible.
3. Configure the OAuth consent/login experience and access policy for only authorized users. Use an Auth0 custom domain if required by your discovery flow.
4. Set the following Railway service variables (never commit secrets):
   - `MCP_TRANSPORT=http`
   - `MCP_AUTH_TOKEN=<existing-long-secret>` (retain for legacy clients)
   - `SCRAPECREATORS_API_KEY=<secret>`
   - `AUTH0_ISSUER=https://YOUR_TENANT.auth0.com/`
   - `AUTH0_AUDIENCE=<exact Auth0 API identifier>`
   - `MCP_PUBLIC_URL=https://facebook-ad-library-mcp-production.up.railway.app/mcp`
5. Deploy to a **staging Railway service first**, not production. Verify `GET /.well-known/oauth-protected-resource` returns a metadata document, unauthenticated `POST /mcp` returns 401 with a `WWW-Authenticate` resource metadata hint, and an Auth0 JWT issued for the exact API audience permits MCP initialize and tools/list. Verify an expired token, wrong issuer, wrong audience, and invalid signature all return 401. Verify the old bearer token still works.
6. Only then test ChatGPT OAuth discovery/registration and consent flow. If ChatGPT reports client-registration failure, configure the explicit OAuth client ID/secret (if supported) or a compatible OAuth provider; this server's protected-resource metadata alone cannot solve it.

## Known limitations and safeguards

- The existing FastMCP version is pinned to `2.6.1`; this implementation uses the existing `mcp.streamable_http_app()` ASGI interface and wraps it, avoiding newer FastMCP auth APIs. Full integration remains untested.
- Auth0 may issue opaque access tokens or JWTs for other audiences; only **RS256 JWT access tokens** for `AUTH0_AUDIENCE` are accepted here.
- Configure Auth0 access policies to restrict users and API audience. This code validates signature, issuer, audience and expiry, but does not enforce a custom scope or a specific user allowlist.
- Production is unaffected until this branch is merged/deployed. Never disable bearer protection as a workaround.
- This repository's Meta search tools are brand/Page-ID oriented; the seven global keyword discovery searches requested for dropshipping require additional API capability and separate implementation.
