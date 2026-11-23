# HavenHub requirements

Each requirement has an ID. Every ID must be covered by at least one test tagged with it
(`[Test("REQ-07")]`); the test runner fails the build if any requirement is left without a test
and prints the traceability matrix (`dotnet run --project tests/HavenHub.Tests -- --matrix`).

| ID | Requirement | Source |
|---|---|---|
| REQ-01 | Accounts need a password of 12–128 characters that is not on the common-password blocklist; passwords are stored only as PBKDF2-HMAC-SHA256 hashes (600,000 iterations by default). | NIST SP 800-63B, OWASP |
| REQ-02 | After 5 failed logins an account is locked for 15 minutes. Unknown email and wrong password give the same response. | OWASP ASVS V2 |
| REQ-03 | API access uses signed, expiring bearer tokens that can be revoked everywhere at once ("sign out everywhere", account deletion). | OWASP ASVS V3 |
| REQ-04 | Each home has Owner, Member and Guest roles. Users who are not members of a home get 404 for anything in it, so home ids cannot be probed. | Least privilege |
| REQ-05 | Devices are paired with single-use pairing codes that expire after 10 minutes. Each device gets its own random 256-bit secret; there are no default or shared credentials. | ETSI EN 303 645 §5.1 |
| REQ-06 | Device secrets are encrypted at rest with AES-256-GCM, bound to the device serial. | ETSI EN 303 645 §5.4 |
| REQ-07 | Every device message, in both directions, is authenticated with HMAC-SHA256. Messages that are tampered with, stale (over 60 s clock skew), out of order or replayed are rejected. | ETSI EN 303 645 §5.5 |
| REQ-08 | Devices whose firmware is older than the configured minimum are refused at pairing and at connection. | ETSI EN 303 645 §5.3 |
| REQ-09 | Commands are validated for each device type: allowed actions, argument ranges, and safety interlocks (garage door will not close onto an obstruction; a jammed lock will not be told to lock). | Product safety |
| REQ-10 | Every command is tracked to a final status (Acked, Failed, TimedOut, Expired). Sent commands time out if the device does not answer, and a late answer cannot change a final status. | Reliability |
| REQ-11 | Commands are idempotent per user and idempotency key: a retried request returns the original command and is not executed twice. Reusing a key for a different command is refused. | Reliability |
| REQ-12 | Comfort commands (lights, thermostat) wait up to 5 minutes for an offline device and are delivered when it reconnects. Security commands (lock, garage door) fail at once if the device is offline. | Product safety |
| REQ-13 | The security panel arms Stay or Away. Arming is refused while a perimeter sensor is open unless bypassed. Away arming has an exit delay. A perimeter opening while armed starts an entry delay and triggers the alarm if not disarmed in time. Interior motion triggers Away mode at once and is ignored in Stay mode. Tamper triggers at once. | Alarm panel behaviour |
| REQ-14 | Disarming needs the home's PIN (4–8 digits, weak PINs refused, stored hashed). After 5 wrong PINs disarming is locked for 5 minutes. | Alarm panel behaviour |
| REQ-15 | Device state reports are merged into the stored state, and changes that matter (door opened or closed, motion, doorbell press, lock state, jam, obstruction, low battery, tamper) are recorded as events and passed to the panel in the same transaction. | Core function |
| REQ-16 | Event history is returned newest first with keyset pagination served by an index. | Performance |
| REQ-17 | Reports give daily activity per event type and per-device command reliability (sent, acknowledged, failed, average acknowledgement time) computed in SQL. | Reporting |
| REQ-18 | The dashboard receives live home events through Server-Sent Events. | User experience |
| REQ-19 | Security-relevant actions are written to an append-only audit log whose entries are hash-chained, so any edit or deletion is detected. | ETSI EN 303 645 §5.7, ASVS V7 |
| REQ-20 | Owners can delete a home and users can delete their account; all related devices, commands and events are removed. | ETSI EN 303 645 §5.11 |
| REQ-21 | Login and registration, device pairing, PIN attempts and commands are rate-limited, each in its own bucket. | OWASP API4:2023 |
| REQ-22 | Responses carry security headers (strict CSP, nosniff, frame denial, no referrer, no-store for API) and request bodies are capped at 64 KB. | OWASP Secure Headers |
| REQ-23 | Devices that stop sending heartbeats are marked offline; on start-up every device is offline until it reconnects. | Reliability |
| REQ-24 | All SQL uses bound parameters. The schema is created by versioned migrations, each applied once in a transaction. | OWASP A03, maintainability |
| REQ-25 | The HTML5 dashboard is served by the API under the strict CSP (no inline scripts or styles). | Front end |
