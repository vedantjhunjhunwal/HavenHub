# ADR-0002: Devices connect over a WebSocket with HMAC-signed messages

Status: Accepted

## Context
Devices sit behind home NAT, so the cloud cannot call them; they must keep an outbound connection
open for commands. Every message must be authentic in both directions: a forged "unlock" or a forged
"door closed" is a security failure. Options: MQTT broker, HTTPS long-polling, WebSocket.

## Decision
One WebSocket per device to `/device/ws`, carried over TLS in production. Each JSON envelope
`{t, s, q, ts, n, b, sig}` is signed with HMAC-SHA256 under the device's own 256-bit secret over
`type|serial|seq|ts|nonce|body`. The receiver checks the signature (constant-time compare), clock skew
(60 s), sequence (strictly increasing per connection) and nonce (unique per device, stored until it
falls outside the skew window). The body is a JSON *string* so the signature covers exact bytes.

## Consequences
+ No broker to run; the same ASP.NET Core process handles REST, SSE and devices.
+ Message-level authentication still holds if TLS terminates at a proxy.
+ A bad frame is dropped without dropping the connection, so one corrupted message cannot knock a lock offline.
- One process holds the sockets. Scaling out needs sticky routing or a pub/sub hop between nodes.
