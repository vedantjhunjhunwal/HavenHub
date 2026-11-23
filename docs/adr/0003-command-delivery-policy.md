# ADR-0003: Command delivery – idempotent, tracked to a final state, safety-aware offline policy

Status: Accepted

## Context
Phones retry on flaky networks; devices drop off Wi-Fi; a user may tap "open garage" and walk away.

## Decision
- Every command row has a status that always reaches a final value (Acked, Failed, TimedOut, Expired).
- `(user_id, idempotency_key)` is unique; retries return the original command.
- Comfort commands (lights, thermostat) may wait up to 5 minutes for an offline device and are sent
  when it reconnects. Security and safety commands (locks, garage door) fail at once if the device is
  offline: unlocking a door ten minutes after the user gave up is worse than failing.
- Completion updates are conditional on the row still being in flight, so late acks are ignored.

## Consequences
+ Users always learn what happened; nothing runs twice; nothing unsafe runs late.
- Owners see "device offline" for a lock and must retry when it is back.
