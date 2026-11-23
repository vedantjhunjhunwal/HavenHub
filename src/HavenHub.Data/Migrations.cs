using HavenHub.Data.Sqlite;

namespace HavenHub.Data;

/// <summary>
/// Versioned, forward-only schema migrations. Each runs in its own transaction and is recorded in
/// schema_migrations, so starting the service against an existing database only applies what is new.
/// </summary>
public static class Migrations
{
    public static readonly IReadOnlyList<(int Version, string Name, string Sql)> All =
    [
        (1, "initial schema", """
            CREATE TABLE users (
                id              INTEGER PRIMARY KEY,
                email           TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                password_hash   TEXT    NOT NULL,
                failed_logins   INTEGER NOT NULL DEFAULT 0,
                locked_until    INTEGER,
                token_version   INTEGER NOT NULL DEFAULT 1,
                created_at      INTEGER NOT NULL
            );

            CREATE TABLE homes (
                id              INTEGER PRIMARY KEY,
                name            TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
                mode            TEXT    NOT NULL DEFAULT 'Disarmed' CHECK (mode IN ('Disarmed','ArmedStay','ArmedAway')),
                alarm           TEXT    NOT NULL DEFAULT 'Idle' CHECK (alarm IN ('Idle','ExitDelay','EntryDelay','Triggered')),
                deadline        INTEGER,
                pin_hash        TEXT    NOT NULL,
                pin_failures    INTEGER NOT NULL DEFAULT 0,
                pin_locked_until INTEGER,
                created_at      INTEGER NOT NULL
            );
            -- The panel ticker only looks at homes with a running delay.
            CREATE INDEX ix_homes_deadline ON homes(deadline) WHERE deadline IS NOT NULL;

            CREATE TABLE home_members (
                home_id         INTEGER NOT NULL REFERENCES homes(id) ON DELETE CASCADE,
                user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                role            TEXT    NOT NULL CHECK (role IN ('Guest','Member','Owner')),
                PRIMARY KEY (home_id, user_id)
            );
            CREATE INDEX ix_home_members_user ON home_members(user_id);

            CREATE TABLE devices (
                id              INTEGER PRIMARY KEY,
                home_id         INTEGER NOT NULL REFERENCES homes(id) ON DELETE CASCADE,
                kind            TEXT    NOT NULL,
                name            TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
                zone            TEXT    NOT NULL CHECK (zone IN ('None','Perimeter','Interior')),
                serial          TEXT    NOT NULL UNIQUE,
                secret_enc      BLOB    NOT NULL,
                firmware        TEXT    NOT NULL,
                state           TEXT    NOT NULL DEFAULT '{}',
                state_version   INTEGER NOT NULL DEFAULT 0,
                online          INTEGER NOT NULL DEFAULT 0,
                last_seen       INTEGER,
                created_at      INTEGER NOT NULL
            );
            CREATE INDEX ix_devices_home ON devices(home_id);
            CREATE INDEX ix_devices_online_seen ON devices(last_seen) WHERE online = 1;

            CREATE TABLE pairing_codes (
                code_digest     TEXT    PRIMARY KEY,
                home_id         INTEGER NOT NULL REFERENCES homes(id) ON DELETE CASCADE,
                kind            TEXT    NOT NULL,
                name            TEXT    NOT NULL,
                zone            TEXT    NOT NULL,
                expires_at      INTEGER NOT NULL,
                used_at         INTEGER
            );

            CREATE TABLE commands (
                id              INTEGER PRIMARY KEY,
                device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                home_id         INTEGER NOT NULL REFERENCES homes(id) ON DELETE CASCADE,
                user_id         INTEGER NOT NULL,
                idempotency_key TEXT    NOT NULL,
                action          TEXT    NOT NULL,
                args            TEXT    NOT NULL DEFAULT '{}',
                status          TEXT    NOT NULL CHECK (status IN ('Pending','Sent','Acked','Failed','TimedOut','Expired')),
                error           TEXT,
                created_at      INTEGER NOT NULL,
                expires_at      INTEGER NOT NULL,
                sent_at         INTEGER,
                completed_at    INTEGER,
                UNIQUE (user_id, idempotency_key)
            );
            CREATE INDEX ix_commands_device_status ON commands(device_id, status, id);
            CREATE INDEX ix_commands_open ON commands(status, sent_at) WHERE status IN ('Pending','Sent');

            CREATE TABLE events (
                id              INTEGER PRIMARY KEY,
                home_id         INTEGER NOT NULL REFERENCES homes(id) ON DELETE CASCADE,
                device_id       INTEGER,
                type            TEXT    NOT NULL,
                detail          TEXT    NOT NULL DEFAULT '',
                at              INTEGER NOT NULL
            );
            -- Keyset pagination: newest first, ties broken by id.
            CREATE INDEX ix_events_home_at ON events(home_id, at DESC, id DESC);

            CREATE TABLE device_nonces (
                device_id       INTEGER NOT NULL,
                nonce           TEXT    NOT NULL,
                at              INTEGER NOT NULL,
                PRIMARY KEY (device_id, nonce)
            ) WITHOUT ROWID;
            CREATE INDEX ix_device_nonces_at ON device_nonces(at);

            CREATE TABLE audit_log (
                id              INTEGER PRIMARY KEY,
                at              INTEGER NOT NULL,
                user_id         INTEGER,
                home_id         INTEGER,
                action          TEXT    NOT NULL,
                detail          TEXT    NOT NULL,
                prev_hash       TEXT    NOT NULL,
                hash            TEXT    NOT NULL UNIQUE
            );
            CREATE INDEX ix_audit_home ON audit_log(home_id, id);
            """),
    ];

    public static int Apply(SqliteConnection c)
    {
        c.Execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)");
        var current = c.Scalar("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations");
        var applied = 0;
        foreach (var (version, name, sql) in All.Where(m => m.Version > current).OrderBy(m => m.Version))
        {
            c.Transaction(tx =>
            {
                foreach (var statement in SplitStatements(sql))
                {
                    tx.Execute(statement);
                }

                return tx.Execute(
                    "INSERT INTO schema_migrations(version, name, applied_at) VALUES ($v, $n, $t)",
                    ("$v", version), ("$n", name), ("$t", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
            });
            applied++;
        }

        return applied;
    }

    // Statements in migrations never contain ';' inside literals, so a plain split is safe here.
    private static IEnumerable<string> SplitStatements(string sql) =>
        sql.Split(';').Select(s => string.Join('\n', s.Split('\n').Where(l => !l.TrimStart().StartsWith("--", StringComparison.Ordinal))).Trim())
           .Where(s => s.Length > 0);
}
