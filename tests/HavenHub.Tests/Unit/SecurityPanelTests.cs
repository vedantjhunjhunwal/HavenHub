using HavenHub.Core.Devices;
using HavenHub.Core.Security;
using HavenHub.Tests.Framework;

namespace HavenHub.Tests.Unit;

public sealed class SecurityPanelTests
{
    private static readonly PanelSettings Cfg = new(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(60));
    private const long T0 = 1_000_000;

    private static PanelState ArmedAwayIdle() =>
        SecurityPanel.Tick(SecurityPanel.Arm(PanelState.Disarmed, ArmMode.ArmedAway, [], false, T0, Cfg).State, T0 + 60_000).State;

    [Test("REQ-13")]
    public void Arming_away_starts_exit_delay_then_settles()
    {
        var r = SecurityPanel.Arm(PanelState.Disarmed, ArmMode.ArmedAway, [], false, T0, Cfg);
        Assert.True(r.Ok);
        Assert.Equal(AlarmState.ExitDelay, r.State.Alarm);
        Assert.Equal(T0 + 60_000, r.State.DeadlineMs);
        Assert.Equal(AlarmState.ExitDelay, SecurityPanel.Tick(r.State, T0 + 59_999).State.Alarm, "one ms before deadline");
        var settled = SecurityPanel.Tick(r.State, T0 + 60_000);
        Assert.Equal(AlarmState.Idle, settled.State.Alarm);
        Assert.Equal("exit_delay_ended", settled.Event);
    }

    [Test("REQ-13")]
    public void Arming_is_refused_with_an_open_perimeter_sensor_unless_bypassed()
    {
        var refused = SecurityPanel.Arm(PanelState.Disarmed, ArmMode.ArmedStay, ["Back door"], false, T0, Cfg);
        Assert.False(refused.Ok);
        Assert.Contains("Back door", refused.Error);
        Assert.True(SecurityPanel.Arm(PanelState.Disarmed, ArmMode.ArmedStay, ["Back door"], true, T0, Cfg).Ok, "bypass");
    }

    [Test("REQ-13")]
    public void Arming_twice_is_refused()
    {
        var armed = SecurityPanel.Arm(PanelState.Disarmed, ArmMode.ArmedStay, [], false, T0, Cfg).State;
        Assert.Equal("already_armed", SecurityPanel.Arm(armed, ArmMode.ArmedAway, [], false, T0, Cfg).Error);
    }

    [Test("REQ-13")]
    public void Sensors_are_ignored_during_exit_delay()
    {
        var exiting = SecurityPanel.Arm(PanelState.Disarmed, ArmMode.ArmedAway, [], false, T0, Cfg).State;
        Assert.Equal(AlarmState.ExitDelay, SecurityPanel.OnSignal(exiting, SignalType.ContactOpened, Zone.Perimeter, T0 + 5_000, Cfg).State.Alarm);
        Assert.Equal(AlarmState.ExitDelay, SecurityPanel.OnSignal(exiting, SignalType.Motion, Zone.Interior, T0 + 5_000, Cfg).State.Alarm);
    }

    [Test("REQ-13")]
    public void Perimeter_opening_starts_entry_delay_and_alarm_fires_when_it_runs_out()
    {
        var opened = SecurityPanel.OnSignal(ArmedAwayIdle(), SignalType.ContactOpened, Zone.Perimeter, T0 + 100_000, Cfg);
        Assert.Equal(AlarmState.EntryDelay, opened.State.Alarm);
        Assert.Equal(T0 + 130_000, opened.State.DeadlineMs);
        Assert.Equal(AlarmState.EntryDelay, SecurityPanel.Tick(opened.State, T0 + 129_999).State.Alarm);
        var fired = SecurityPanel.Tick(opened.State, T0 + 130_000);
        Assert.Equal(AlarmState.Triggered, fired.State.Alarm);
        Assert.Equal("alarm_triggered:entry_timeout", fired.Event);
    }

    [Test("REQ-13")]
    public void Disarming_during_entry_delay_prevents_the_alarm()
    {
        var opened = SecurityPanel.OnSignal(ArmedAwayIdle(), SignalType.ContactOpened, Zone.Perimeter, T0 + 100_000, Cfg).State;
        var disarmed = SecurityPanel.Disarm(opened);
        Assert.Equal(PanelState.Disarmed, disarmed.State);
        Assert.Equal("disarmed", disarmed.Event);
        Assert.Equal(PanelState.Disarmed, SecurityPanel.Tick(disarmed.State, T0 + 999_999).State, "no alarm later");
    }

    [Test("REQ-13")]
    public void A_second_opening_does_not_restart_the_entry_delay()
    {
        var first = SecurityPanel.OnSignal(ArmedAwayIdle(), SignalType.ContactOpened, Zone.Perimeter, T0 + 100_000, Cfg).State;
        var second = SecurityPanel.OnSignal(first, SignalType.ContactOpened, Zone.Perimeter, T0 + 120_000, Cfg).State;
        Assert.Equal(first.DeadlineMs, second.DeadlineMs);
    }

    [Test("REQ-13")]
    public void Interior_motion_triggers_away_but_not_stay()
    {
        Assert.Equal(AlarmState.Triggered, SecurityPanel.OnSignal(ArmedAwayIdle(), SignalType.Motion, Zone.Interior, T0 + 100_000, Cfg).State.Alarm);
        var stay = SecurityPanel.Arm(PanelState.Disarmed, ArmMode.ArmedStay, [], false, T0, Cfg).State;
        Assert.Equal(AlarmState.Idle, SecurityPanel.OnSignal(stay, SignalType.Motion, Zone.Interior, T0 + 1, Cfg).State.Alarm);
    }

    [Test("REQ-13")]
    public void Motion_during_entry_delay_follows_the_entry_route_instead_of_triggering()
    {
        var entering = SecurityPanel.OnSignal(ArmedAwayIdle(), SignalType.ContactOpened, Zone.Perimeter, T0 + 100_000, Cfg).State;
        Assert.Equal(AlarmState.EntryDelay, SecurityPanel.OnSignal(entering, SignalType.Motion, Zone.Interior, T0 + 105_000, Cfg).State.Alarm);
    }

    [Test("REQ-13")]
    public void Tamper_triggers_immediately_when_armed_and_is_ignored_when_disarmed()
    {
        var stay = SecurityPanel.Arm(PanelState.Disarmed, ArmMode.ArmedStay, [], false, T0, Cfg).State;
        Assert.Equal("alarm_triggered:tamper", SecurityPanel.OnSignal(stay, SignalType.Tamper, Zone.None, T0, Cfg).Event);
        Assert.Equal(PanelState.Disarmed, SecurityPanel.OnSignal(PanelState.Disarmed, SignalType.Tamper, Zone.None, T0, Cfg).State);
    }

    [Test("REQ-13")]
    public void Disarming_a_triggered_alarm_records_cancellation_and_disarming_twice_is_a_no_op()
    {
        var triggered = SecurityPanel.OnSignal(ArmedAwayIdle(), SignalType.Motion, Zone.Interior, T0 + 100_000, Cfg).State;
        Assert.Equal("alarm_cancelled", SecurityPanel.Disarm(triggered).Event);
        Assert.Equal(null, SecurityPanel.Disarm(PanelState.Disarmed).Event);
    }
}
