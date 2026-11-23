using HavenHub.Core.Devices;
using HavenHub.Core.Security;
using HavenHub.Data;
using HavenHub.Data.Sqlite;
using HavenHub.Tests.Framework;

namespace HavenHub.Tests.Data;

/// <summary>Repository and SQL behaviour against a real SQLite file.</summary>
public sealed class DataTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("havenhub-data-").FullName;
    private readonly Database _db;

    public DataTests() => _db = new Database(Path.Combine(_dir, "test.db"));

    public void Dispose()
    {
        _db.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    private (long Home, long Device, long User) Seed()
    {
        return _db.Transaction(c =>
        {
            var user = UserRepository.Create(c, "a@example.com", "hash", 1);
            var home = HomeRepository.Create(c, "Home", "pin", user, 1);
            var device = DeviceRepository.Create(c, home, DeviceKind.Light, "Lamp", Zone.None, "LAMP-0001", [1, 2, 3], "2.0.0", 1);
            return (home, device, user);
        });
    }

    [Test("REQ-24")]
    public void Migrations_are_versioned_and_applied_once()
    {
        Assert.Equal(1L, _db.Read(c => c.Scalar("SELECT MAX(version) AS v FROM schema_migrations")));
        Assert.Equal(0, _db.Write(Migrations.Apply), "re-running applies nothing");
        var tables = _db.Read(c => c.Query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name", r => r.Text("name")));
        foreach (var t in new[] { "audit_log", "commands", "device_nonces", "devices", "events", "home_members", "homes", "pairing_codes", "users" })
        {
            Assert.True(tables.Contains(t), "table " + t);
        }
    }

    [Test("REQ-24")]
    public void Values_are_bound_as_parameters_so_injection_text_is_stored_literally()
    {
        var payload = "Robert'); DROP TABLE users;--";
        var id = _db.Write(c => UserRepository.Create(c, payload + "@example.com", "h", 1));
        Assert.Equal(payload + "@example.com", _db.Read(c => UserRepository.ById(c, id))!.Email);
        Assert.Equal(1L, _db.Read(c => c.Scalar("SELECT COUNT(*) AS v FROM users")), "users table intact");
    }

    [Test("REQ-24")]
    public void A_failed_transaction_rolls_back_every_statement()
    {
        var (home, _, _) = Seed();
        Assert.Throws<DbException>(() => _db.Transaction(c =>
        {
            EventRepository.Add(c, home, null, "first", "", 10);
            EventRepository.Add(c, 99_999, null, "violates foreign key", "", 11);
        }));
        Assert.Equal(0L, _db.Read(c => c.Scalar("SELECT COUNT(*) AS v FROM events")), "first insert rolled back");
    }

    [Test("REQ-24")]
    public void Constraints_are_enforced_by_the_schema()
    {
        Seed();
        var dup = Assert.Throws<DbException>(() => _db.Write(c => UserRepository.Create(c, "A@EXAMPLE.COM", "h", 1)));
        Assert.True(dup.IsConstraint, "email unique, case-insensitive");
        Assert.Throws<DbException>(() => _db.Write(c => c.Execute("UPDATE homes SET mode = 'Party'")));
    }

    [Test("REQ-16")]
    public void Keyset_pagination_walks_all_events_newest_first_without_gaps_or_repeats()
    {
        var (home, _, _) = Seed();
        _db.Transaction(c =>
        {
            for (var i = 0; i < 250; i++)
            {
                EventRepository.Add(c, home, null, "e" + i, "", 1000 + (i / 3)); // several events share a timestamp
            }
        });

        var seen = new List<long>();
        long? at = null, id = null;
        while (true)
        {
            var page = _db.Read(c => EventRepository.Page(c, home, at, id, 40));
            seen.AddRange(page.Select(e => e.Id));
            if (page.Count < 40)
            {
                break;
            }

            (at, id) = (page[^1].AtMs, page[^1].Id);
        }

        Assert.Equal(250, seen.Count);
        Assert.Equal(250, seen.Distinct().Count(), "no repeats");
        Assert.True(seen.SequenceEqual(seen.OrderByDescending(x => x)), "newest first");
    }

    [Test("REQ-16", "REQ-24")]
    public void Hot_queries_are_served_by_indexes()
    {
        string Plan(string sql) => string.Join(" | ", _db.Read(c => c.Query("EXPLAIN QUERY PLAN " + sql, r => r.Text("detail"))));
        Assert.Contains("ix_events_home_at", Plan("SELECT * FROM events WHERE home_id = 1 AND (at, id) < (5, 5) ORDER BY at DESC, id DESC LIMIT 50"), "events page");
        Assert.Contains("ix_commands_device_status", Plan("SELECT * FROM commands WHERE device_id = 1 AND status = 'Pending' AND expires_at > 0 ORDER BY id"), "pending commands");
        Assert.Contains("ix_homes_deadline", Plan("SELECT id FROM homes WHERE deadline IS NOT NULL AND deadline <= 5"), "panel ticker");
        Assert.Contains("ix_home_members_user", Plan("SELECT * FROM home_members WHERE user_id = 3"), "homes for user");
    }

    [Test("REQ-17")]
    public void Reports_aggregate_activity_and_command_reliability_in_sql()
    {
        var (home, device, user) = Seed();
        _db.Transaction(c =>
        {
            EventRepository.Add(c, home, device, "device:Motion", "", 86_400_000L * 2);
            EventRepository.Add(c, home, device, "device:Motion", "", (86_400_000L * 2) + 5);
            EventRepository.Add(c, home, device, "panel:armed_away", "", 86_400_000L * 3);
            var ok = CommandRepository.Create(c, device, home, user, "k1", "on", "{}", CommandStatus.Pending, null, 100, 10_000);
            CommandRepository.MarkSent(c, ok, 100);
            CommandRepository.Complete(c, ok, device, true, null, 140);
            var slow = CommandRepository.Create(c, device, home, user, "k2", "on", "{}", CommandStatus.Pending, null, 200, 10_000);
            CommandRepository.MarkSent(c, slow, 200);
            CommandRepository.Complete(c, slow, device, true, null, 260);
            CommandRepository.Create(c, device, home, user, "k3", "on", "{}", CommandStatus.Failed, "device_offline", 300, 300);
        });

        var daily = _db.Read(c => EventRepository.DailyCounts(c, home, 0));
        Assert.Equal(("1970-01-03", "device:Motion", 2L), daily[0]);
        Assert.Equal(("1970-01-04", "panel:armed_away", 1L), daily[1]);
        var reliability = _db.Read(c => EventRepository.CommandReliability(c, home, 0)).Single();
        Assert.Equal(("Lamp", 3L, 2L, 1L, (long?)50L), reliability);
    }

    [Test("REQ-10")]
    public void A_late_ack_cannot_overwrite_a_timed_out_command()
    {
        var (home, device, user) = Seed();
        var id = _db.Write(c => CommandRepository.Create(c, device, home, user, "k", "on", "{}", CommandStatus.Pending, null, 0, 60_000));
        _db.Write(c => CommandRepository.MarkSent(c, id, 0));
        var swept = _db.Transaction(c => CommandRepository.Sweep(c, 10_000, 10_000));
        Assert.Equal(1, swept.Count);
        Assert.False(_db.Write(c => CommandRepository.Complete(c, id, device, true, null, 10_500)), "late ack ignored");
        Assert.Equal(CommandStatus.TimedOut, _db.Read(c => CommandRepository.ById(c, id))!.Status);
    }

    [Test("REQ-05")]
    public void A_pairing_code_can_be_claimed_once_and_not_after_expiry()
    {
        var (home, _, _) = Seed();
        _db.Write(c => DeviceRepository.AddPairingCode(c, "d1", home, DeviceKind.Lock, "Door", Zone.Perimeter, 1_000));
        _db.Write(c => DeviceRepository.AddPairingCode(c, "d2", home, DeviceKind.Lock, "Door", Zone.Perimeter, 1_000));
        Assert.NotNull(_db.Write(c => DeviceRepository.ClaimPairingCode(c, "d1", 500)));
        Assert.Equal(null, _db.Write(c => DeviceRepository.ClaimPairingCode(c, "d1", 600)), "second use");
        Assert.Equal(null, _db.Write(c => DeviceRepository.ClaimPairingCode(c, "d2", 1_000)), "expired");
        Assert.Equal(null, _db.Write(c => DeviceRepository.ClaimPairingCode(c, "nope", 1)), "unknown");
    }

    [Test("REQ-07")]
    public void Nonces_detect_replays_until_pruned()
    {
        var (_, device, _) = Seed();
        Assert.True(_db.Write(c => DeviceRepository.TryUseNonce(c, device, "N1", 100)));
        Assert.False(_db.Write(c => DeviceRepository.TryUseNonce(c, device, "N1", 200)), "replay");
        Assert.Equal(1, _db.Write(c => DeviceRepository.PruneNonces(c, 150)));
    }

    [Test("REQ-19")]
    public void Audit_chain_detects_edits_and_deletions()
    {
        _db.Transaction(c =>
        {
            for (var i = 0; i < 5; i++)
            {
                AuditRepository.Append(c, 1, 1, "action" + i, "detail", i);
            }
        });
        Assert.Equal(null, _db.Read(AuditRepository.FirstBrokenLink), "intact");

        _db.Write(c => c.Execute("UPDATE audit_log SET detail = 'edited' WHERE id = 3"));
        Assert.Equal(3L, _db.Read(AuditRepository.FirstBrokenLink), "edit found at 3");

        _db.Write(c => c.Execute("UPDATE audit_log SET detail = 'detail' WHERE id = 3"));
        _db.Write(c => c.Execute("DELETE FROM audit_log WHERE id = 2"));
        Assert.Equal(3L, _db.Read(AuditRepository.FirstBrokenLink), "deletion breaks the link at 3");
    }

    [Test("REQ-20")]
    public void Deleting_a_home_cascades_to_devices_commands_and_events()
    {
        var (home, device, user) = Seed();
        _db.Transaction(c =>
        {
            EventRepository.Add(c, home, device, "x", "", 1);
            CommandRepository.Create(c, device, home, user, "k", "on", "{}", CommandStatus.Pending, null, 1, 2);
            HomeRepository.Delete(c, home);
        });
        foreach (var table in new[] { "devices", "commands", "events", "home_members" })
        {
            Assert.Equal(0L, _db.Read(c => c.Scalar($"SELECT COUNT(*) AS v FROM {table}")), table);
        }
    }

    [Test("REQ-23")]
    public void Startup_marks_every_device_offline()
    {
        var (_, device, _) = Seed();
        _db.Write(c => DeviceRepository.SetOnline(c, device, true, null, 5));
        Assert.Equal(1, _db.Write(DeviceRepository.MarkAllOffline));
        Assert.False(_db.Read(c => DeviceRepository.ById(c, device))!.Online);
    }

    [Test("REQ-24")]
    public void Concurrent_readers_and_a_writer_share_the_database_safely()
    {
        var (home, _, _) = Seed();
        var writer = Task.Run(() =>
        {
            for (var i = 0; i < 500; i++)
            {
                _db.Write(c => EventRepository.Add(c, home, null, "w", "", i));
            }
        });
        var readers = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            long last = 0;
            while (!writer.IsCompleted)
            {
                var n = _db.Read(c => c.Scalar("SELECT COUNT(*) AS v FROM events"));
                Assert.True(n >= last, "count never goes backwards");
                last = n;
            }
        })).ToArray();
        Task.WaitAll([writer, .. readers]);
        Assert.Equal(500L, _db.Read(c => c.Scalar("SELECT COUNT(*) AS v FROM events")));
    }

    [Test("REQ-01")]
    public void Login_failures_lock_the_account_at_the_threshold()
    {
        var (_, _, user) = Seed();
        for (var i = 0; i < 4; i++)
        {
            _db.Write(c => UserRepository.RecordLoginFailure(c, user, 5, 9_999));
        }

        Assert.Equal(null, _db.Read(c => UserRepository.ById(c, user))!.LockedUntilMs, "4 failures");
        _db.Write(c => UserRepository.RecordLoginFailure(c, user, 5, 9_999));
        Assert.Equal(9_999L, _db.Read(c => UserRepository.ById(c, user))!.LockedUntilMs, "5th failure locks");
        _ = PasswordHasher.DefaultIterations;
    }
}
