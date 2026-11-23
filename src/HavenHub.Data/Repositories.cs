using HavenHub.Core.Devices;
using HavenHub.Core.Security;
using HavenHub.Data.Sqlite;

namespace HavenHub.Data;

public sealed record User(long Id, string Email, string PasswordHash, int FailedLogins, long? LockedUntilMs, int TokenVersion);

public sealed record Home(long Id, string Name, PanelState Panel, string PinHash, int PinFailures, long? PinLockedUntilMs);

public sealed record Membership(long HomeId, long UserId, HomeRole Role, string HomeName);

public sealed record Device(
    long Id, long HomeId, DeviceKind Kind, string Name, Zone Zone, string Serial, byte[] SecretEnc,
    string Firmware, string StateJson, long StateVersion, bool Online, long? LastSeenMs);

public enum CommandStatus
{
    Pending,
    Sent,
    Acked,
    Failed,
    TimedOut,
    Expired,
}

public sealed record CommandRow(
    long Id, long DeviceId, long HomeId, long UserId, string IdempotencyKey, string Action, string ArgsJson,
    CommandStatus Status, string? Error, long CreatedMs, long ExpiresMs, long? SentMs, long? CompletedMs)
{
    public bool IsFinal => Status is CommandStatus.Acked or CommandStatus.Failed or CommandStatus.TimedOut or CommandStatus.Expired;
}

public sealed record EventRow(long Id, long HomeId, long? DeviceId, string Type, string Detail, long AtMs);

public sealed record AuditRow(long Id, long AtMs, long? UserId, long? HomeId, string Action, string Detail, string PrevHash, string Hash);

public sealed record PairingRow(long HomeId, DeviceKind Kind, string Name, Zone Zone, long ExpiresMs, long? UsedMs);

/// <summary>Users and their login state.</summary>
public static class UserRepository
{
    private const string Cols = "id, email, password_hash, failed_logins, locked_until, token_version";

    public static long Create(SqliteConnection c, string email, string passwordHash, long nowMs)
    {
        c.Execute(
            "INSERT INTO users(email, password_hash, created_at) VALUES ($e, $p, $t)",
            ("$e", email), ("$p", passwordHash), ("$t", nowMs));
        return c.LastInsertRowId;
    }

    public static User? ByEmail(SqliteConnection c, string email) =>
        c.QuerySingle($"SELECT {Cols} FROM users WHERE email = $e", Map, ("$e", email));

    public static User? ById(SqliteConnection c, long id) =>
        c.QuerySingle($"SELECT {Cols} FROM users WHERE id = $id", Map, ("$id", id));

    public static void RecordLoginFailure(SqliteConnection c, long id, int maxFailures, long lockUntilMs) => c.Execute(
        """
        UPDATE users
           SET failed_logins = failed_logins + 1,
               locked_until  = CASE WHEN failed_logins + 1 >= $max THEN $until ELSE locked_until END
         WHERE id = $id
        """,
        ("$id", id), ("$max", maxFailures), ("$until", lockUntilMs));

    public static void RecordLoginSuccess(SqliteConnection c, long id) =>
        c.Execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $id", ("$id", id));

    public static void RevokeTokens(SqliteConnection c, long id) =>
        c.Execute("UPDATE users SET token_version = token_version + 1 WHERE id = $id", ("$id", id));

    public static int Delete(SqliteConnection c, long id) => c.Execute("DELETE FROM users WHERE id = $id", ("$id", id));

    private static User Map(Row r) => new(
        r.Num("id"), r.Text("email"), r.Text("password_hash"), (int)r.Num("failed_logins"), r.NumOrNull("locked_until"), (int)r.Num("token_version"));
}

/// <summary>Homes, their security panel state and membership.</summary>
public static class HomeRepository
{
    private const string Cols = "id, name, mode, alarm, deadline, pin_hash, pin_failures, pin_locked_until";

    public static long Create(SqliteConnection c, string name, string pinHash, long ownerId, long nowMs)
    {
        c.Execute("INSERT INTO homes(name, pin_hash, created_at) VALUES ($n, $p, $t)", ("$n", name), ("$p", pinHash), ("$t", nowMs));
        var id = c.LastInsertRowId;
        AddMember(c, id, ownerId, HomeRole.Owner);
        return id;
    }

    public static Home? ById(SqliteConnection c, long id) =>
        c.QuerySingle($"SELECT {Cols} FROM homes WHERE id = $id", Map, ("$id", id));

    public static HomeRole? RoleOf(SqliteConnection c, long homeId, long userId)
    {
        var role = c.QuerySingle(
            "SELECT role FROM home_members WHERE home_id = $h AND user_id = $u", r => r.Text("role"), ("$h", homeId), ("$u", userId));
        return role is null ? null : Enum.Parse<HomeRole>(role);
    }

    public static List<Membership> ForUser(SqliteConnection c, long userId) => c.Query(
        """
        SELECT m.home_id, m.user_id, m.role, h.name
          FROM home_members m JOIN homes h ON h.id = m.home_id
         WHERE m.user_id = $u
         ORDER BY h.name, h.id
        """,
        r => new Membership(r.Num("home_id"), r.Num("user_id"), Enum.Parse<HomeRole>(r.Text("role")), r.Text("name")),
        ("$u", userId));

    public static List<(long UserId, string Email, HomeRole Role)> Members(SqliteConnection c, long homeId) => c.Query(
        "SELECT u.id, u.email, m.role FROM home_members m JOIN users u ON u.id = m.user_id WHERE m.home_id = $h ORDER BY u.email",
        r => (r.Num("id"), r.Text("email"), Enum.Parse<HomeRole>(r.Text("role"))),
        ("$h", homeId));

    public static void AddMember(SqliteConnection c, long homeId, long userId, HomeRole role) => c.Execute(
        "INSERT INTO home_members(home_id, user_id, role) VALUES ($h, $u, $r) ON CONFLICT(home_id, user_id) DO UPDATE SET role = excluded.role",
        ("$h", homeId), ("$u", userId), ("$r", role));

    public static int RemoveMember(SqliteConnection c, long homeId, long userId) =>
        c.Execute("DELETE FROM home_members WHERE home_id = $h AND user_id = $u", ("$h", homeId), ("$u", userId));

    public static long OwnerCount(SqliteConnection c, long homeId) =>
        c.Scalar("SELECT COUNT(*) AS v FROM home_members WHERE home_id = $h AND role = 'Owner'", ("$h", homeId));

    public static void SavePanel(SqliteConnection c, long homeId, PanelState s) => c.Execute(
        "UPDATE homes SET mode = $m, alarm = $a, deadline = $d WHERE id = $id",
        ("$id", homeId), ("$m", s.Mode), ("$a", s.Alarm), ("$d", s.DeadlineMs));

    public static void RecordPinFailure(SqliteConnection c, long homeId, int maxFailures, long lockUntilMs) => c.Execute(
        """
        UPDATE homes
           SET pin_failures     = pin_failures + 1,
               pin_locked_until = CASE WHEN pin_failures + 1 >= $max THEN $until ELSE pin_locked_until END
         WHERE id = $id
        """,
        ("$id", homeId), ("$max", maxFailures), ("$until", lockUntilMs));

    public static void ResetPinFailures(SqliteConnection c, long homeId) =>
        c.Execute("UPDATE homes SET pin_failures = 0, pin_locked_until = NULL WHERE id = $id", ("$id", homeId));

    /// <summary>Homes whose exit or entry delay has run out (served by the partial index on deadline).</summary>
    public static List<long> DueForTick(SqliteConnection c, long nowMs) =>
        c.Query("SELECT id FROM homes WHERE deadline IS NOT NULL AND deadline <= $now", r => r.Num("id"), ("$now", nowMs));

    public static int Delete(SqliteConnection c, long homeId) => c.Execute("DELETE FROM homes WHERE id = $id", ("$id", homeId));

    /// <summary>Homes left with no members after a user deletes their account.</summary>
    public static int DeleteOrphans(SqliteConnection c) =>
        c.Execute("DELETE FROM homes WHERE NOT EXISTS (SELECT 1 FROM home_members m WHERE m.home_id = homes.id AND m.role = 'Owner')");

    private static Home Map(Row r) => new(
        r.Num("id"),
        r.Text("name"),
        new PanelState(Enum.Parse<ArmMode>(r.Text("mode")), Enum.Parse<AlarmState>(r.Text("alarm")), r.NumOrNull("deadline")),
        r.Text("pin_hash"),
        (int)r.Num("pin_failures"),
        r.NumOrNull("pin_locked_until"));
}

/// <summary>Paired devices, their last reported state and connectivity.</summary>
public static class DeviceRepository
{
    private const string Cols = "id, home_id, kind, name, zone, serial, secret_enc, firmware, state, state_version, online, last_seen";

    public static long Create(SqliteConnection c, long homeId, DeviceKind kind, string name, Zone zone, string serial, byte[] secretEnc, string firmware, long nowMs)
    {
        c.Execute(
            """
            INSERT INTO devices(home_id, kind, name, zone, serial, secret_enc, firmware, created_at)
            VALUES ($h, $k, $n, $z, $s, $sec, $fw, $t)
            """,
            ("$h", homeId), ("$k", kind), ("$n", name), ("$z", zone), ("$s", serial), ("$sec", secretEnc), ("$fw", firmware), ("$t", nowMs));
        return c.LastInsertRowId;
    }

    public static Device? ById(SqliteConnection c, long id) => c.QuerySingle($"SELECT {Cols} FROM devices WHERE id = $id", Map, ("$id", id));

    public static Device? BySerial(SqliteConnection c, string serial) =>
        c.QuerySingle($"SELECT {Cols} FROM devices WHERE serial = $s", Map, ("$s", serial));

    public static List<Device> ForHome(SqliteConnection c, long homeId) =>
        c.Query($"SELECT {Cols} FROM devices WHERE home_id = $h ORDER BY name, id", Map, ("$h", homeId));

    public static void SaveState(SqliteConnection c, long id, string stateJson, long nowMs) => c.Execute(
        "UPDATE devices SET state = $st, state_version = state_version + 1, last_seen = $t WHERE id = $id",
        ("$id", id), ("$st", stateJson), ("$t", nowMs));

    public static void SetOnline(SqliteConnection c, long id, bool online, string? firmware, long nowMs) => c.Execute(
        "UPDATE devices SET online = $o, firmware = COALESCE($fw, firmware), last_seen = $t WHERE id = $id",
        ("$id", id), ("$o", online), ("$fw", firmware), ("$t", nowMs));

    /// <summary>At start-up no device can be connected yet, whatever the last run recorded.</summary>
    public static int MarkAllOffline(SqliteConnection c) => c.Execute("UPDATE devices SET online = 0 WHERE online = 1");

    public static void Touch(SqliteConnection c, long id, long nowMs) =>
        c.Execute("UPDATE devices SET last_seen = $t WHERE id = $id", ("$id", id), ("$t", nowMs));

    /// <summary>Online devices that have gone quiet for longer than the heartbeat timeout.</summary>
    public static List<Device> Silent(SqliteConnection c, long olderThanMs) =>
        c.Query($"SELECT {Cols} FROM devices WHERE online = 1 AND last_seen < $cut", Map, ("$cut", olderThanMs));

    public static int Delete(SqliteConnection c, long id) => c.Execute("DELETE FROM devices WHERE id = $id", ("$id", id));

    /// <summary>Records a message nonce; returns false if the device already used it (a replay).</summary>
    public static bool TryUseNonce(SqliteConnection c, long deviceId, string nonce, long nowMs) =>
        c.Execute("INSERT OR IGNORE INTO device_nonces(device_id, nonce, at) VALUES ($d, $n, $t)", ("$d", deviceId), ("$n", nonce), ("$t", nowMs)) == 1;

    public static int PruneNonces(SqliteConnection c, long olderThanMs) =>
        c.Execute("DELETE FROM device_nonces WHERE at < $cut", ("$cut", olderThanMs));

    public static void AddPairingCode(SqliteConnection c, string digest, long homeId, DeviceKind kind, string name, Zone zone, long expiresMs) => c.Execute(
        "INSERT INTO pairing_codes(code_digest, home_id, kind, name, zone, expires_at) VALUES ($c, $h, $k, $n, $z, $e)",
        ("$c", digest), ("$h", homeId), ("$k", kind), ("$n", name), ("$z", zone), ("$e", expiresMs));

    /// <summary>Atomically claims an unused, unexpired pairing code. Returns null if it is unknown, used or expired.</summary>
    public static PairingRow? ClaimPairingCode(SqliteConnection c, string digest, long nowMs)
    {
        var claimed = c.Execute(
            "UPDATE pairing_codes SET used_at = $t WHERE code_digest = $c AND used_at IS NULL AND expires_at > $t",
            ("$c", digest), ("$t", nowMs));
        return claimed == 0
            ? null
            : c.QuerySingle(
                "SELECT home_id, kind, name, zone, expires_at, used_at FROM pairing_codes WHERE code_digest = $c",
                r => new PairingRow(r.Num("home_id"), Enum.Parse<DeviceKind>(r.Text("kind")), r.Text("name"), Enum.Parse<Zone>(r.Text("zone")), r.Num("expires_at"), r.NumOrNull("used_at")),
                ("$c", digest));
    }

    private static Device Map(Row r) => new(
        r.Num("id"), r.Num("home_id"), Enum.Parse<DeviceKind>(r.Text("kind")), r.Text("name"), Enum.Parse<Zone>(r.Text("zone")),
        r.Text("serial"), r.Blob("secret_enc") ?? [], r.Text("firmware"), r.Text("state"), r.Num("state_version"), r.Bool("online"), r.NumOrNull("last_seen"));
}

/// <summary>Command lifecycle: Pending -> Sent -> Acked | Failed | TimedOut, or Pending -> Expired.</summary>
public static class CommandRepository
{
    private const string Cols = "id, device_id, home_id, user_id, idempotency_key, action, args, status, error, created_at, expires_at, sent_at, completed_at";

    public static long Create(SqliteConnection c, long deviceId, long homeId, long userId, string key, string action, string argsJson, CommandStatus status, string? error, long nowMs, long expiresMs)
    {
        c.Execute(
            """
            INSERT INTO commands(device_id, home_id, user_id, idempotency_key, action, args, status, error, created_at, expires_at, completed_at)
            VALUES ($d, $h, $u, $k, $a, $args, $s, $e, $t, $x, CASE WHEN $s IN ('Failed','Expired') THEN $t END)
            """,
            ("$d", deviceId), ("$h", homeId), ("$u", userId), ("$k", key), ("$a", action), ("$args", argsJson),
            ("$s", status), ("$e", error), ("$t", nowMs), ("$x", expiresMs));
        return c.LastInsertRowId;
    }

    public static CommandRow? ById(SqliteConnection c, long id) => c.QuerySingle($"SELECT {Cols} FROM commands WHERE id = $id", Map, ("$id", id));

    public static CommandRow? ByIdempotencyKey(SqliteConnection c, long userId, string key) =>
        c.QuerySingle($"SELECT {Cols} FROM commands WHERE user_id = $u AND idempotency_key = $k", Map, ("$u", userId), ("$k", key));

    /// <summary>Queued commands for a device that has just connected, oldest first.</summary>
    public static List<CommandRow> PendingFor(SqliteConnection c, long deviceId, long nowMs) => c.Query(
        $"SELECT {Cols} FROM commands WHERE device_id = $d AND status = 'Pending' AND expires_at > $t ORDER BY id",
        Map, ("$d", deviceId), ("$t", nowMs));

    public static bool MarkSent(SqliteConnection c, long id, long nowMs) =>
        c.Execute("UPDATE commands SET status = 'Sent', sent_at = $t WHERE id = $id AND status = 'Pending'", ("$id", id), ("$t", nowMs)) == 1;

    /// <summary>
    /// Records the device's answer. Only a command still in flight can complete, so a late ack after a
    /// timeout cannot rewrite history.
    /// </summary>
    public static bool Complete(SqliteConnection c, long id, long deviceId, bool ok, string? error, long nowMs) => c.Execute(
        """
        UPDATE commands SET status = $s, error = $e, completed_at = $t
         WHERE id = $id AND device_id = $d AND status IN ('Pending','Sent')
        """,
        ("$id", id), ("$d", deviceId), ("$s", ok ? CommandStatus.Acked : CommandStatus.Failed), ("$e", error), ("$t", nowMs)) == 1;

    /// <summary>Times out sent commands with no answer and expires queued ones; returns the affected rows.</summary>
    public static List<CommandRow> Sweep(SqliteConnection c, long nowMs, long ackTimeoutMs)
    {
        var due = c.Query(
            $"""
            SELECT {Cols} FROM commands
             WHERE (status = 'Sent' AND sent_at <= $cut) OR (status = 'Pending' AND expires_at <= $now)
            """,
            Map, ("$cut", nowMs - ackTimeoutMs), ("$now", nowMs));
        foreach (var cmd in due)
        {
            c.Execute(
                "UPDATE commands SET status = $s, error = $e, completed_at = $t WHERE id = $id AND status IN ('Pending','Sent')",
                ("$id", cmd.Id),
                ("$s", cmd.Status == CommandStatus.Sent ? CommandStatus.TimedOut : CommandStatus.Expired),
                ("$e", cmd.Status == CommandStatus.Sent ? "no_ack_from_device" : "device_offline_until_expiry"),
                ("$t", nowMs));
        }

        return due;
    }

    private static CommandRow Map(Row r) => new(
        r.Num("id"), r.Num("device_id"), r.Num("home_id"), r.Num("user_id"), r.Text("idempotency_key"), r.Text("action"), r.Text("args"),
        Enum.Parse<CommandStatus>(r.Text("status")), r.TextOrNull("error"), r.Num("created_at"), r.Num("expires_at"), r.NumOrNull("sent_at"), r.NumOrNull("completed_at"));
}

/// <summary>Home activity history and reports.</summary>
public static class EventRepository
{
    public static long Add(SqliteConnection c, long homeId, long? deviceId, string type, string detail, long nowMs)
    {
        c.Execute(
            "INSERT INTO events(home_id, device_id, type, detail, at) VALUES ($h, $d, $ty, $de, $t)",
            ("$h", homeId), ("$d", deviceId), ("$ty", type), ("$de", detail), ("$t", nowMs));
        return c.LastInsertRowId;
    }

    /// <summary>
    /// Keyset pagination, newest first: pass the (at, id) of the last row seen to get the next page.
    /// Unlike OFFSET, the cost does not grow with page depth and rows inserted meanwhile are not skipped.
    /// </summary>
    public static List<EventRow> Page(SqliteConnection c, long homeId, long? beforeAt, long? beforeId, int limit) => c.Query(
        """
        SELECT id, home_id, device_id, type, detail, at FROM events
         WHERE home_id = $h AND ($ba IS NULL OR (at, id) < ($ba, $bi))
         ORDER BY at DESC, id DESC
         LIMIT $lim
        """,
        Map, ("$h", homeId), ("$ba", beforeAt), ("$bi", beforeId ?? long.MaxValue), ("$lim", limit));

    /// <summary>Events per day and type for the last <paramref name="sinceMs"/> window.</summary>
    public static List<(string Day, string Type, long Count)> DailyCounts(SqliteConnection c, long homeId, long sinceMs) => c.Query(
        """
        SELECT date(at / 1000, 'unixepoch') AS day, type, COUNT(*) AS n
          FROM events
         WHERE home_id = $h AND at >= $since
         GROUP BY day, type
         ORDER BY day, type
        """,
        r => (r.Text("day"), r.Text("type"), r.Num("n")), ("$h", homeId), ("$since", sinceMs));

    /// <summary>Per-device command reliability: how many were sent, acknowledged, and how fast.</summary>
    public static List<(string Device, long Total, long Acked, long Failed, long? AvgAckMs)> CommandReliability(SqliteConnection c, long homeId, long sinceMs) => c.Query(
        """
        SELECT d.name                                                   AS device,
               COUNT(cmd.id)                                            AS total,
               COALESCE(SUM(cmd.status = 'Acked'), 0)                   AS acked,
               COALESCE(SUM(cmd.status IN ('Failed','TimedOut','Expired')), 0) AS failed,
               CAST(AVG(CASE WHEN cmd.status = 'Acked' THEN cmd.completed_at - cmd.sent_at END) AS INTEGER) AS avg_ack_ms
          FROM devices d
          LEFT JOIN commands cmd ON cmd.device_id = d.id AND cmd.created_at >= $since
         WHERE d.home_id = $h
         GROUP BY d.id
         ORDER BY d.name
        """,
        r => (r.Text("device"), r.Num("total"), r.Num("acked"), r.Num("failed"), r.NumOrNull("avg_ack_ms")),
        ("$h", homeId), ("$since", sinceMs));

    private static EventRow Map(Row r) => new(r.Num("id"), r.Num("home_id"), r.NumOrNull("device_id"), r.Text("type"), r.Text("detail"), r.Num("at"));
}

/// <summary>Append-only, hash-chained audit log of security-relevant actions.</summary>
public static class AuditRepository
{
    public static AuditRow Append(SqliteConnection c, long? userId, long? homeId, string action, string detail, long nowMs)
    {
        var prev = c.QuerySingle("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1", r => r.Text("hash")) ?? AuditChain.Genesis;
        var hash = AuditChain.HashEntry(prev, nowMs, userId, homeId, action, detail);
        c.Execute(
            "INSERT INTO audit_log(at, user_id, home_id, action, detail, prev_hash, hash) VALUES ($t, $u, $h, $a, $d, $p, $x)",
            ("$t", nowMs), ("$u", userId), ("$h", homeId), ("$a", action), ("$d", detail), ("$p", prev), ("$x", hash));
        return new AuditRow(c.LastInsertRowId, nowMs, userId, homeId, action, detail, prev, hash);
    }

    public static List<AuditRow> ForHome(SqliteConnection c, long homeId, int limit) => c.Query(
        "SELECT id, at, user_id, home_id, action, detail, prev_hash, hash FROM audit_log WHERE home_id = $h ORDER BY id DESC LIMIT $l",
        Map, ("$h", homeId), ("$l", limit));

    /// <summary>Recomputes the whole chain. Returns the id of the first entry that does not match, or null if intact.</summary>
    public static long? FirstBrokenLink(SqliteConnection c)
    {
        var expectedPrev = AuditChain.Genesis;
        foreach (var row in c.Query("SELECT id, at, user_id, home_id, action, detail, prev_hash, hash FROM audit_log ORDER BY id", Map))
        {
            if (row.PrevHash != expectedPrev || row.Hash != AuditChain.HashEntry(row.PrevHash, row.AtMs, row.UserId, row.HomeId, row.Action, row.Detail))
            {
                return row.Id;
            }

            expectedPrev = row.Hash;
        }

        return null;
    }

    private static AuditRow Map(Row r) => new(
        r.Num("id"), r.Num("at"), r.NumOrNull("user_id"), r.NumOrNull("home_id"), r.Text("action"), r.Text("detail"), r.Text("prev_hash"), r.Text("hash"));
}
