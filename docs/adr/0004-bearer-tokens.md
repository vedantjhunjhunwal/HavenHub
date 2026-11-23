# ADR-0004: Compact HMAC bearer tokens with a per-user version

Status: Accepted

## Context
The API needs stateless authentication for the dashboard and apps, with the ability to revoke all
sessions (lost phone, account deletion). JWT libraries are third-party packages (ADR-0001).

## Decision
Token = `base64url(json{UserId, Version, ExpiresMs})` + "." + `base64url(HMAC-SHA256(key, payload))`,
lifetime 60 minutes. The authentication handler verifies the MAC in constant time, checks expiry and
compares `Version` with `users.token_version`. "Sign out everywhere" and account deletion bump the
version, which invalidates every outstanding token at once. The dashboard keeps the token in memory
only and sends it in the `Authorization` header (never in a URL, cookie or browser storage).

## Consequences
+ No package; one indexed lookup per request also confirms the user still exists.
- Not interoperable with third-party JWT tooling (not needed here).
