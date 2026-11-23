using System.Text.Json.Nodes;
using HavenHub.Api.Infrastructure;
using HavenHub.Core;
using HavenHub.Core.Devices;
using HavenHub.Core.Security;
using HavenHub.Data;
using HavenHub.Data.Sqlite;

namespace HavenHub.Api.Services;

public sealed record SecurityStatus(ArmMode Mode, AlarmState Alarm, long? DeadlineMs, IReadOnlyList<string> OpenSensors, bool PinLocked);

/// <summary>Arms, disarms and drives each home's <see cref="SecurityPanel"/>, persisting every transition.</summary>
public sealed class SecurityService(Database db, IClock clock, HavenHubOptions options, EventHub hub)
{
    public SecurityStatus? Status(long homeId) => db.Read(c =>
    {
        var home = HomeRepository.ById(c, homeId);
        return home is null
            ? null
            : new SecurityStatus(home.Panel.Mode, home.Panel.Alarm, home.Panel.DeadlineMs, OpenPerimeter(c, homeId), home.PinLockedUntilMs > clock.NowMs);
    });

    public IResult Arm(long homeId, long userId, ArmMode mode, bool bypass)
    {
        var now = clock.NowMs;
        var result = db.Transaction(c =>
        {
            var home = HomeRepository.ById(c, homeId)!;
            var r = SecurityPanel.Arm(home.Panel, mode, OpenPerimeter(c, homeId), bypass, now, options.Panel);
            if (r.Ok)
            {
                Persist(c, homeId, null, r, userId, now);
            }

            return r;
        });

        if (!result.Ok)
        {
            return result.Error == "already_armed" ? ApiError.Conflict(result.Error) : ApiError.Unprocessable(result.Error!);
        }

        Announce(homeId, result);
        return Results.Ok(Status(homeId));
    }

    public IResult Disarm(long homeId, long userId, string pin)
    {
        var now = clock.NowMs;
        var outcome = db.Transaction(c =>
        {
            var home = HomeRepository.ById(c, homeId)!;
            if (home.PinLockedUntilMs > now)
            {
                return ("pin_locked", (PanelResult?)null);
            }

            if (!PasswordHasher.Verify(pin, home.PinHash))
            {
                HomeRepository.RecordPinFailure(c, homeId, options.MaxPinFailures, now + (options.PinLockoutMinutes * 60_000L));
                AuditRepository.Append(c, userId, homeId, "disarm_failed", "wrong PIN", now);
                return ("wrong_pin", null);
            }

            HomeRepository.ResetPinFailures(c, homeId);
            var r = SecurityPanel.Disarm(home.Panel);
            Persist(c, homeId, null, r, userId, now);
            return ((string?)null, r);
        });

        switch (outcome)
        {
            case ("pin_locked", _):
                return ApiError.TooMany("pin_locked");
            case ("wrong_pin", _):
                return ApiError.Forbidden("wrong_pin");
        }

        Announce(homeId, outcome.Item2!);
        return Results.Ok(Status(homeId));
    }

    /// <summary>Feeds a device signal to the panel inside the caller's transaction.</summary>
    public PanelResult ApplySignal(SqliteConnection c, long homeId, long deviceId, SignalType signal, Zone zone, long now)
    {
        var home = HomeRepository.ById(c, homeId)!;
        var r = SecurityPanel.OnSignal(home.Panel, signal, zone, now, options.Panel);
        Persist(c, homeId, deviceId, r, null, now);
        return r;
    }

    /// <summary>Ends exit delays and fires alarms whose entry delay ran out.</summary>
    public int Tick()
    {
        var now = clock.NowMs;
        var due = db.Read(c => HomeRepository.DueForTick(c, now));
        foreach (var homeId in due)
        {
            var r = db.Transaction(c =>
            {
                var home = HomeRepository.ById(c, homeId);
                if (home is null)
                {
                    return null;
                }

                var result = SecurityPanel.Tick(home.Panel, now);
                Persist(c, homeId, null, result, null, now);
                return result;
            });
            if (r is not null)
            {
                Announce(homeId, r);
            }
        }

        return due.Count;
    }

    public void Announce(long homeId, PanelResult r)
    {
        if (r.Event is not null)
        {
            hub.Publish(homeId, "panel", new { r.State.Mode, r.State.Alarm, r.State.DeadlineMs, @event = r.Event });
        }
    }

    private static void Persist(SqliteConnection c, long homeId, long? deviceId, PanelResult r, long? userId, long now)
    {
        if (r.Event is null)
        {
            return;
        }

        HomeRepository.SavePanel(c, homeId, r.State);
        EventRepository.Add(c, homeId, deviceId, "panel:" + r.Event, r.State.Mode.ToString(), now);
        AuditRepository.Append(c, userId, homeId, "panel:" + r.Event, r.State.Mode.ToString(), now);
    }

    private static List<string> OpenPerimeter(SqliteConnection c, long homeId) =>
        DeviceRepository.ForHome(c, homeId)
            .Where(d => d.Zone == Zone.Perimeter && JsonNode.Parse(d.StateJson) is JsonObject s && s["open"] is JsonValue v && v.TryGetValue(out bool open) && open)
            .Select(d => d.Name)
            .ToList();
}
