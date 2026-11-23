using HavenHub.Core.Devices;

namespace HavenHub.Core.Security;

public enum ArmMode
{
    Disarmed,
    ArmedStay,
    ArmedAway,
}

public enum AlarmState
{
    Idle,
    ExitDelay,
    EntryDelay,
    Triggered,
}

public sealed record PanelState(ArmMode Mode, AlarmState Alarm, long? DeadlineMs)
{
    public static readonly PanelState Disarmed = new(ArmMode.Disarmed, AlarmState.Idle, null);
}

public sealed record PanelSettings(TimeSpan EntryDelay, TimeSpan ExitDelay)
{
    public static readonly PanelSettings Default = new(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(60));
}

/// <summary>Outcome of a panel operation. <see cref="Event"/> is set when something worth recording happened.</summary>
public sealed record PanelResult(bool Ok, string? Error, PanelState State, string? Event)
{
    public static PanelResult Fail(PanelState s, string error) => new(false, error, s, null);

    public static PanelResult Same(PanelState s) => new(true, null, s, null);

    public static PanelResult Moved(PanelState s, string evt) => new(true, null, s, evt);
}

/// <summary>
/// Pure state machine for a home's security panel. It has no I/O, so every transition is unit-tested
/// with explicit times. Rules follow common residential panels:
/// <list type="bullet">
/// <item>Arming is refused while a perimeter sensor is open, unless the user bypasses it.</item>
/// <item>Armed Away starts an exit delay during which sensors are ignored.</item>
/// <item>A perimeter opening while armed starts an entry delay; disarming within it prevents the alarm.</item>
/// <item>Interior motion while Armed Away (with no entry delay running) triggers at once; it is ignored in Armed Stay.</item>
/// <item>Tamper while armed triggers at once.</item>
/// </list>
/// </summary>
public static class SecurityPanel
{
    public static PanelResult Arm(PanelState s, ArmMode mode, IReadOnlyCollection<string> openPerimeter, bool bypass, long nowMs, PanelSettings cfg)
    {
        if (mode == ArmMode.Disarmed)
        {
            return PanelResult.Fail(s, "use_disarm");
        }

        if (s.Mode != ArmMode.Disarmed)
        {
            return PanelResult.Fail(s, "already_armed");
        }

        if (openPerimeter.Count > 0 && !bypass)
        {
            return PanelResult.Fail(s, "open_sensors: " + string.Join(", ", openPerimeter));
        }

        return mode == ArmMode.ArmedAway
            ? PanelResult.Moved(new PanelState(mode, AlarmState.ExitDelay, nowMs + (long)cfg.ExitDelay.TotalMilliseconds), "armed_away")
            : PanelResult.Moved(new PanelState(mode, AlarmState.Idle, null), "armed_stay");
    }

    public static PanelResult Disarm(PanelState s) =>
        s.Mode == ArmMode.Disarmed && s.Alarm == AlarmState.Idle
            ? PanelResult.Same(s)
            : PanelResult.Moved(PanelState.Disarmed, s.Alarm == AlarmState.Triggered ? "alarm_cancelled" : "disarmed");

    public static PanelResult OnSignal(PanelState s, SignalType signal, Zone zone, long nowMs, PanelSettings cfg)
    {
        if (s.Mode == ArmMode.Disarmed || s.Alarm == AlarmState.Triggered)
        {
            return PanelResult.Same(s);
        }

        if (signal == SignalType.Tamper)
        {
            return PanelResult.Moved(new PanelState(s.Mode, AlarmState.Triggered, null), "alarm_triggered:tamper");
        }

        if (s.Alarm == AlarmState.ExitDelay && nowMs < s.DeadlineMs)
        {
            return PanelResult.Same(s);
        }

        if (signal == SignalType.ContactOpened && zone == Zone.Perimeter && s.Alarm != AlarmState.EntryDelay)
        {
            return PanelResult.Moved(
                new PanelState(s.Mode, AlarmState.EntryDelay, nowMs + (long)cfg.EntryDelay.TotalMilliseconds), "entry_delay_started");
        }

        if (signal == SignalType.Motion && zone == Zone.Interior && s.Mode == ArmMode.ArmedAway && s.Alarm != AlarmState.EntryDelay)
        {
            return PanelResult.Moved(new PanelState(s.Mode, AlarmState.Triggered, null), "alarm_triggered:motion");
        }

        return PanelResult.Same(s);
    }

    /// <summary>Advance time-based transitions: end of exit delay, expiry of entry delay.</summary>
    public static PanelResult Tick(PanelState s, long nowMs)
    {
        if (s.DeadlineMs is not { } deadline || nowMs < deadline)
        {
            return PanelResult.Same(s);
        }

        return s.Alarm switch
        {
            AlarmState.ExitDelay => PanelResult.Moved(s with { Alarm = AlarmState.Idle, DeadlineMs = null }, "exit_delay_ended"),
            AlarmState.EntryDelay => PanelResult.Moved(s with { Alarm = AlarmState.Triggered, DeadlineMs = null }, "alarm_triggered:entry_timeout"),
            _ => PanelResult.Same(s),
        };
    }
}
