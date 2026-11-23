# Threat model (STRIDE)

Assets: control of locks and garage doors; the alarm state; device secrets; account credentials;
activity history (shows when a home is empty).

Trust boundaries: browser/app <-> API (internet); device <-> gateway (internet, behind home NAT);
API <-> database (same host).

| # | Threat | STRIDE | Mitigation | Test |
|---|---|---|---|---|
| T1 | Attacker impersonates a lock to report "locked" while it is open | Spoofing | Per-device secret; HMAC on every message; hello must verify before any message is accepted | `Devices_with_the_wrong_secret_cannot_connect` |
| T2 | Attacker replays a captured "door closed" report | Tampering / Spoofing | Nonce store, 60 s freshness window, per-connection sequence | `Replayed_tampered_and_stale_reports_are_dropped` |
| T3 | Fake cloud sends "unlock" to a device | Spoofing | Devices verify the cloud's signature with the shared secret; unsigned commands are dropped | `A_command_travels_to_the_device...` (RejectedFromCloud = 0) |
| T4 | User of home A controls a device in home B by guessing ids | Elevation of privilege | Membership check per request; device must belong to the home in the path; 404 for non-members | `Non_members_get_404_for_everything_in_someone_elses_home` |
| T5 | Guest unlocks the front door | Elevation of privilege | Per-action minimum role (`Lock.unlock` needs Member) | `Guests_can_use_comfort_devices_but_not_unlock_arm_or_manage` |
| T6 | Burglar brute-forces the disarm PIN | Elevation of privilege | Hashed PIN, lockout after 5 failures, per-token PIN rate limit, failures audited | `Disarming_needs_the_pin_and_repeated_wrong_pins_lock_it` |
| T7 | Credential stuffing against login | Spoofing | Lockout, IP rate limit, uniform responses, PBKDF2 cost | `Five_wrong_passwords_lock_the_account...`, `Login_attempts_are_rate_limited_per_client` |
| T8 | Stolen database reveals device secrets | Information disclosure | AES-256-GCM with the key outside the DB; only digests of pairing codes | `Device_secrets_are_never_stored_in_plain_text` |
| T9 | Insider edits the audit log to hide an unlock | Repudiation / Tampering | Hash chain; `chainIntact` reported to owners | `Audit_chain_detects_edits_and_deletions` |
| T10 | Retried request unlocks twice / late ack rewrites history | Tampering | Idempotency keys; conditional completion | `Retrying_with_the_same_idempotency_key...`, `A_late_ack_cannot_overwrite...` |
| T11 | Unlock queued while lock offline runs hours later | Safety | Security commands are never queued | `Comfort_commands_wait_for_an_offline_device_but_security_commands_fail_fast` |
| T12 | Flood of requests or huge payloads exhausts the service | Denial of service | Rate limits per bucket; 64 KB bodies; 16 KB frames; bounded SSE queues | `Login_attempts_are_rate_limited_per_client`, `Responses_carry_security_headers_and_large_bodies_are_refused` |
| T13 | XSS in a device or home name steals the token | Information disclosure | CSP without inline script; `textContent` only; token held in memory | `Dashboard_is_html5_with_no_inline_code` |
| T14 | SQL injection through names | Tampering | Bound parameters only; CA2100 enforced | `Sql_in_user_input_is_stored_as_plain_text` |

Out of scope for this project: physical attacks on devices, firmware signing, multi-node deployment.
