# Backlog and sprint log

HavenHub is planned as user stories with acceptance criteria, grouped into three sprint-sized
increments, each with a goal and a shared Definition of Done. Each story links to the requirements it
delivers.

**Definition of Done:** builds with zero analyzer warnings; every acceptance criterion has a passing
test tagged with its REQ id; CI green; docs updated; security impact noted in the PR template.

## Increment 1 – "A device can be paired and controlled safely"

| Story | Acceptance criteria | REQ | Status |
|---|---|---|---|
| As a home owner I can create an account and sign in | Password policy; hashed storage; lockout; revocable tokens | 01, 02, 03 | Done |
| As an owner I can pair a device with a one-time code | Single use; 10-minute expiry; unique device secret; secret encrypted at rest | 05, 06 | Done |
| As a device I connect with mutual authentication | Signed hello; signed messages both ways; replay and stale rejection; old firmware refused | 07, 08 | Done |
| As a user I can lock or unlock my door from my phone | Round trip with ack; device error surfaced; timeout if no answer | 09, 10 | Done |
| As a developer I get fast feedback | Analyzers as errors; test runner; CI on every push | 24 | Done |

## Increment 2 – "The house protects itself"

| Story | Acceptance criteria | REQ | Status |
|---|---|---|---|
| As an owner I can arm Stay or Away | Open-sensor check with bypass; exit delay | 13 | Done |
| As an owner I am alerted to a break-in | Entry delay; alarm when it runs out; motion and tamper rules | 13, 15 | Done |
| As an owner I disarm with a PIN | Hashed PIN; lockout after 5 failures | 14 | Done |
| As a parent I can let a babysitter use lights but not the door | Guest role; per-action permissions; 404 for outsiders | 04 | Done |
| As a user retrying on bad signal I never unlock twice | Idempotency keys; conflict on reuse | 11 | Done |
| As a user I don't get surprise actions later | Comfort commands queue 5 min; security commands fail fast | 12 | Done |

## Increment 3 – "Operate it with confidence"

| Story | Acceptance criteria | REQ | Status |
|---|---|---|---|
| As an owner I can see what happened at home | Keyset-paginated history; live updates | 16, 18 | Done |
| As support staff I can see which devices are flaky | Daily activity and per-device ack rate in SQL | 17 | Done |
| As an auditor I can trust the security log | Hash-chained audit with tamper detection | 19 | Done |
| As a user I can delete my data | Delete home; delete account with password | 20 | Done |
| As an operator I can survive abuse | Separate rate-limit buckets; header hardening; size caps | 21, 22 | Done |
| As an owner I know when a device dies | Heartbeat monitoring; offline on restart | 23 | Done |
| As an owner I have a web dashboard | HTML5, strict CSP, live feed | 25 | Done |

## Issues found during development and fixed

- **Disarm returned 429 with the correct PIN** (found by the scripted demo). Pairing seven devices had
  used up the shared per-IP "auth" bucket. Fix: separate buckets for login, pairing, PIN and commands,
  plus a regression test (`Pin_attempts_have_their_own_rate_limit_bucket`).
- **Low-battery and doorbell signals were missed** for integer values built in code (found by unit
  tests). `JsonValue.TryGetValue<double>` fails on int-backed nodes. Fix: numeric reads accept
  double, long, int and decimal.
- **Device offline could be recorded twice** when housekeeping closed a half-open socket (found in
  code review). Fix: housekeeping only aborts the socket and the connection handler records the
  transition once.

## Next (not started)

- Push notifications (APNs/FCM) for alarms.
- Multi-node gateway with sticky routing.
- SQL Server provider behind the same repositories.
