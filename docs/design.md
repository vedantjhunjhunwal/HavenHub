# HavenHub design

HavenHub is the cloud side of a home security and automation system: it lets home owners control
locks, garage doors, thermostats and lights from anywhere, and runs each home's alarm panel.

## Components

```
 Browser (HTML5 dashboard)          Phone app / scripts
        |  REST + SSE (bearer token)        |
        v                                   v
 +---------------------- HavenHub.Api (ASP.NET Core 8) ----------------------+
 |  Endpoints  ->  CommandService  ->  DeviceGateway  <== signed WebSocket ==> devices
 |             ->  SecurityService (panel state machine from Core)            |
 |             ->  DeviceService   (pairing, state reports -> signals)        |
 |  EventHub (SSE fan-out)   Housekeeping (timers, timeouts, heartbeats)      |
 +------------------------------------|---------------------------------------+
                                      v
                     HavenHub.Data: SQL repositories over SQLite (WAL)
```

| Project | Responsibility |
|---|---|
| `HavenHub.Core` | Pure domain logic with no I/O: device types (OOP hierarchy), the alarm panel state machine, password/PIN hashing, tokens, AES-GCM secret storage, the signed device protocol. |
| `HavenHub.Data` | P/Invoke binding to SQLite, a connection with a prepared-statement cache, a single-writer/multi-reader `Database`, versioned migrations and the repositories (all SQL lives here). |
| `HavenHub.Api` | ASP.NET Core minimal API, authentication and authorisation, the device WebSocket gateway, command lifecycle, live events, background housekeeping, the dashboard. |
| `HavenHub.DeviceSim` | Simulated devices that speak the real protocol, a typed API client, a scripted demo and a load generator. |
| `HavenHub.Tests` | Unit, data and in-process integration tests, plus the requirement traceability check. |

## Object model

`DeviceType` is an abstract base class. Each subclass (`SmartLock`, `Thermostat`, `GarageDoor`,
`Light`, `ContactSensor`, `MotionSensor`, `Doorbell`) overrides only what differs:

- `Actions` – the commands it accepts;
- `MinimumRole(action)` – who may send each command (a guest may lock but not unlock);
- `OfflineQueueTtl(action)` – whether a command may wait for an offline device;
- `Validate(...)` – argument ranges and safety interlocks;
- `InterpretSpecific(previous, current)` – which state changes are signals (door opened, motion...).

Shared rules (low battery, tamper) live once in the base class. Adding a device kind means adding
one subclass; the API, command pipeline and panel need no changes (open/closed principle).

## Command lifecycle

```
            +--> Failed (device_offline)            security command, device offline
 request ---+
            +--> Pending --(device connected)--> Sent --ack ok--> Acked
                    |                              |---ack error--> Failed
                    |                              +---no ack in 10 s--> TimedOut
                    +--(offline past 5 min TTL)--> Expired
```

- **Idempotency.** `(user_id, idempotency_key)` is UNIQUE. A retry returns the original row.
- **Late acks.** `Complete` only updates rows still `Pending` or `Sent`, so an ack that arrives
  after a timeout cannot rewrite history.
- **Waiting.** `?wait=true` holds the request until the ack (or the timeout), which gives apps a
  synchronous "door unlocked" answer without polling.

## Alarm panel

`SecurityPanel` is a pure function `(state, input, now) -> (state, event)`. The service persists the
new state, an event and an audit entry in one transaction. Time-based transitions (end of exit
delay, entry delay running out) are driven by `Housekeeping` through a partial index on
`homes(deadline)`, so the timer pass touches only homes with a running delay.

A state report flows: WebSocket frame -> signature/freshness/replay checks -> merge into stored state
-> `DeviceType.Interpret` -> events -> `SecurityPanel.OnSignal` -> panel state, all in one
transaction, then pushed to dashboards over SSE.

## Data

SQLite in WAL mode: one writer connection behind a lock, a pool of reader connections. Every value is
a bound parameter. Indexes were chosen for the hot queries and are checked with
`EXPLAIN QUERY PLAN` in the tests:

| Query | Index |
|---|---|
| Event history page (newest first, keyset) | `ix_events_home_at (home_id, at DESC, id DESC)` |
| Queued commands for a reconnecting device | `ix_commands_device_status (device_id, status, id)` |
| Commands to time out or expire | partial `ix_commands_open` |
| Homes with a running delay | partial `ix_homes_deadline` |
| A user's homes | `ix_home_members_user` |
| Silent devices | partial `ix_devices_online_seen` |

## Measured performance

`scripts/run-demo.sh load --homes 50 --seconds 30 --workers 32` runs 50 homes with 350 devices
connected over signed WebSockets. Telemetry and heartbeats flow while 32 concurrent clients send
commands that each go API -> device -> ack -> API. See the README for the latest numbers. Server and
simulator share one machine, so these are lower bounds.
