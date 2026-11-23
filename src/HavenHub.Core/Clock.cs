namespace HavenHub.Core;

/// <summary>Source of the current time. Injected everywhere so tests can control time.</summary>
public interface IClock
{
    DateTimeOffset UtcNow { get; }

    long NowMs => UtcNow.ToUnixTimeMilliseconds();
}

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

/// <summary>Clock that only moves when told to; used by tests and the scripted demo.</summary>
public sealed class ManualClock : IClock
{
    private long _ms;

    public ManualClock(DateTimeOffset start) => _ms = start.ToUnixTimeMilliseconds();

    public DateTimeOffset UtcNow => DateTimeOffset.FromUnixTimeMilliseconds(Interlocked.Read(ref _ms));

    public void Advance(TimeSpan by) => Interlocked.Add(ref _ms, (long)by.TotalMilliseconds);
}
