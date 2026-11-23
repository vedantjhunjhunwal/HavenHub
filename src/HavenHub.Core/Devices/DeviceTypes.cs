using System.Text.Json.Nodes;

namespace HavenHub.Core.Devices;

public enum DeviceKind
{
    Lock,
    Thermostat,
    GarageDoor,
    Light,
    ContactSensor,
    MotionSensor,
    Doorbell,
}

/// <summary>Where a sensor sits, which decides how the alarm panel reacts to it.</summary>
public enum Zone
{
    None,
    Perimeter,
    Interior,
}

/// <summary>Role of a user in a home. Higher values include the rights of lower ones.</summary>
public enum HomeRole
{
    Guest = 0,
    Member = 1,
    Owner = 2,
}

/// <summary>Something security-relevant that a device report revealed.</summary>
public enum SignalType
{
    ContactOpened,
    ContactClosed,
    Motion,
    DoorbellPressed,
    Locked,
    Unlocked,
    LockJammed,
    GarageObstructed,
    LowBattery,
    Tamper,
}

public sealed record CommandCheck(bool Ok, string? Error)
{
    public static readonly CommandCheck Valid = new(true, null);

    public static CommandCheck Reject(string error) => new(false, error);
}

/// <summary>
/// Behaviour of one kind of device: which commands it accepts, who may send them, whether they can wait
/// for an offline device, how arguments are validated and how its state reports turn into signals.
/// </summary>
public abstract class DeviceType
{
    public const int LowBatteryPercent = 15;

    private static readonly Dictionary<DeviceKind, DeviceType> Registry = new DeviceType[]
    {
        new SmartLock(), new Thermostat(), new GarageDoor(), new Light(),
        new ContactSensor(), new MotionSensor(), new Doorbell(),
    }.ToDictionary(t => t.Kind);

    public abstract DeviceKind Kind { get; }

    /// <summary>Commands the device understands. Sensors accept none.</summary>
    public virtual IReadOnlyCollection<string> Actions => [];

    /// <summary>Zone a newly paired device defaults to.</summary>
    public virtual Zone DefaultZone => Zone.None;

    public static DeviceType For(DeviceKind kind) => Registry[kind];

    public static IEnumerable<DeviceType> All => Registry.Values;

    /// <summary>Lowest role allowed to send <paramref name="action"/>.</summary>
    public virtual HomeRole MinimumRole(string action) => HomeRole.Member;

    /// <summary>
    /// How long a command may wait for an offline device. Zero means fail fast: security and safety
    /// commands (unlock, garage door) must never run minutes after the user stopped watching.
    /// </summary>
    public virtual TimeSpan OfflineQueueTtl(string action) => TimeSpan.Zero;

    public CommandCheck Check(string action, JsonObject args, JsonObject state)
    {
        if (!Actions.Contains(action))
        {
            return CommandCheck.Reject("unsupported_action");
        }

        return Validate(action, args, state);
    }

    protected virtual CommandCheck Validate(string action, JsonObject args, JsonObject state) => CommandCheck.Valid;

    /// <summary>Compare the previous and new state and report what changed that matters.</summary>
    public IEnumerable<SignalType> Interpret(JsonObject previous, JsonObject current)
    {
        if (Rose(previous, current, "tamper"))
        {
            yield return SignalType.Tamper;
        }

        var before = Number(previous, "battery");
        var now = Number(current, "battery");
        if (now is < LowBatteryPercent && before is not < LowBatteryPercent)
        {
            yield return SignalType.LowBattery;
        }

        foreach (var signal in InterpretSpecific(previous, current))
        {
            yield return signal;
        }
    }

    protected virtual IEnumerable<SignalType> InterpretSpecific(JsonObject previous, JsonObject current) => [];

    protected static bool? Flag(JsonObject o, string key) =>
        o.TryGetPropertyValue(key, out var n) && n is JsonValue v && v.TryGetValue(out bool b) ? b : null;

    /// <summary>
    /// Reads a numeric value whatever its CLR backing: values parsed from JSON text read as double, but
    /// values built in code (e.g. <c>["battery"] = 14</c>) are int-backed and would otherwise be missed.
    /// </summary>
    protected static double? Number(JsonObject o, string key)
    {
        if (!o.TryGetPropertyValue(key, out var n) || n is not JsonValue v)
        {
            return null;
        }

        if (v.TryGetValue(out double d))
        {
            return d;
        }

        if (v.TryGetValue(out long l))
        {
            return l;
        }

        if (v.TryGetValue(out int i))
        {
            return i;
        }

        return v.TryGetValue(out decimal m) ? (double)m : null;
    }

    protected static string? Text(JsonObject o, string key) =>
        o.TryGetPropertyValue(key, out var n) && n is JsonValue v && v.TryGetValue(out string? s) ? s : null;

    /// <summary>True when a boolean flag goes from false/missing to true.</summary>
    protected static bool Rose(JsonObject previous, JsonObject current, string key) =>
        Flag(current, key) == true && Flag(previous, key) != true;

    /// <summary>True when a boolean flag goes from true to false.</summary>
    protected static bool Fell(JsonObject previous, JsonObject current, string key) =>
        Flag(current, key) == false && Flag(previous, key) == true;
}

public sealed class SmartLock : DeviceType
{
    public override DeviceKind Kind => DeviceKind.Lock;

    public override IReadOnlyCollection<string> Actions => ["lock", "unlock"];

    public override Zone DefaultZone => Zone.Perimeter;

    // Guests may lock the door behind them but never unlock it.
    public override HomeRole MinimumRole(string action) => action == "lock" ? HomeRole.Guest : HomeRole.Member;

    protected override CommandCheck Validate(string action, JsonObject args, JsonObject state) =>
        action == "lock" && Flag(state, "jammed") == true ? CommandCheck.Reject("lock_jammed") : CommandCheck.Valid;

    protected override IEnumerable<SignalType> InterpretSpecific(JsonObject previous, JsonObject current)
    {
        if (Rose(previous, current, "locked"))
        {
            yield return SignalType.Locked;
        }

        if (Fell(previous, current, "locked"))
        {
            yield return SignalType.Unlocked;
        }

        if (Rose(previous, current, "jammed"))
        {
            yield return SignalType.LockJammed;
        }
    }
}

public sealed class Thermostat : DeviceType
{
    public const double MinSetpoint = 7;
    public const double MaxSetpoint = 32;
    private static readonly string[] Modes = ["heat", "cool", "auto", "off"];

    public override DeviceKind Kind => DeviceKind.Thermostat;

    public override IReadOnlyCollection<string> Actions => ["set_setpoint", "set_mode"];

    public override HomeRole MinimumRole(string action) => HomeRole.Guest;

    public override TimeSpan OfflineQueueTtl(string action) => TimeSpan.FromMinutes(5);

    protected override CommandCheck Validate(string action, JsonObject args, JsonObject state)
    {
        if (action == "set_setpoint")
        {
            var c = Number(args, "celsius");
            return c is >= MinSetpoint and <= MaxSetpoint
                ? CommandCheck.Valid
                : CommandCheck.Reject($"celsius must be between {MinSetpoint} and {MaxSetpoint}");
        }

        return Modes.Contains(Text(args, "mode")) ? CommandCheck.Valid : CommandCheck.Reject("mode must be heat, cool, auto or off");
    }
}

public sealed class GarageDoor : DeviceType
{
    public override DeviceKind Kind => DeviceKind.GarageDoor;

    public override IReadOnlyCollection<string> Actions => ["open", "close"];

    public override Zone DefaultZone => Zone.Perimeter;

    // Never close onto something in the doorway.
    protected override CommandCheck Validate(string action, JsonObject args, JsonObject state) =>
        action == "close" && Flag(state, "obstructed") == true ? CommandCheck.Reject("obstruction_detected") : CommandCheck.Valid;

    protected override IEnumerable<SignalType> InterpretSpecific(JsonObject previous, JsonObject current)
    {
        if (Rose(previous, current, "open"))
        {
            yield return SignalType.ContactOpened;
        }

        if (Fell(previous, current, "open"))
        {
            yield return SignalType.ContactClosed;
        }

        if (Rose(previous, current, "obstructed"))
        {
            yield return SignalType.GarageObstructed;
        }
    }
}

public sealed class Light : DeviceType
{
    public override DeviceKind Kind => DeviceKind.Light;

    public override IReadOnlyCollection<string> Actions => ["on", "off", "dim"];

    public override HomeRole MinimumRole(string action) => HomeRole.Guest;

    public override TimeSpan OfflineQueueTtl(string action) => TimeSpan.FromMinutes(5);

    protected override CommandCheck Validate(string action, JsonObject args, JsonObject state) =>
        action != "dim" || Number(args, "level") is >= 1 and <= 100
            ? CommandCheck.Valid
            : CommandCheck.Reject("level must be between 1 and 100");
}

public sealed class ContactSensor : DeviceType
{
    public override DeviceKind Kind => DeviceKind.ContactSensor;

    public override Zone DefaultZone => Zone.Perimeter;

    protected override IEnumerable<SignalType> InterpretSpecific(JsonObject previous, JsonObject current)
    {
        if (Rose(previous, current, "open"))
        {
            yield return SignalType.ContactOpened;
        }

        if (Fell(previous, current, "open"))
        {
            yield return SignalType.ContactClosed;
        }
    }
}

public sealed class MotionSensor : DeviceType
{
    public override DeviceKind Kind => DeviceKind.MotionSensor;

    public override Zone DefaultZone => Zone.Interior;

    protected override IEnumerable<SignalType> InterpretSpecific(JsonObject previous, JsonObject current)
    {
        if (Rose(previous, current, "motion"))
        {
            yield return SignalType.Motion;
        }
    }
}

public sealed class Doorbell : DeviceType
{
    public override DeviceKind Kind => DeviceKind.Doorbell;

    protected override IEnumerable<SignalType> InterpretSpecific(JsonObject previous, JsonObject current)
    {
        // The doorbell reports a press counter so that a missed report cannot lose a ring.
        if (Number(current, "presses") > (Number(previous, "presses") ?? 0))
        {
            yield return SignalType.DoorbellPressed;
        }
    }
}
