# ADR-0001: No third-party packages; SQLite through P/Invoke

Status: Accepted

## Context
A home-security backend is an attractive target, and every dependency is code we ship but did not
write (supply-chain risk, ETSI EN 303 645 §5.6 "minimise exposed attack surfaces"). The service needs
a relational database, a web framework, crypto and a test harness.

## Decision
Use only the .NET 8 SDK, the ASP.NET Core shared framework and the operating system's SQLite library.
- Data access binds the ~30 SQLite C functions it needs through P/Invoke, wrapped in a small
  `SqliteConnection` with a prepared-statement cache. All values are bound parameters.
- Crypto uses `System.Security.Cryptography` (PBKDF2, HMAC-SHA256, AES-GCM, CSPRNG).
- Tests use a ~150-line runner instead of xUnit; it also enforces requirement traceability.
- `nuget.config` clears every package source so a package cannot be added by accident.

## Consequences
+ Zero third-party packages to audit or patch; CI fails if a `PackageReference` appears.
+ The data layer is small enough to read in one sitting.
- We maintain the binding ourselves (mitigated by data tests and CI on every push).
- SQLite suits one node. Moving to SQL Server or PostgreSQL means re-implementing `SqliteConnection`
  behind the same repository methods; the SQL is standard apart from `INSERT OR IGNORE` and `date()`.
