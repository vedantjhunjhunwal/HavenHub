using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HavenHub.Core.Protocol;

/// <summary>
/// One message on the device WebSocket, in either direction.
/// The body is carried as a JSON string so the signature covers exact bytes, not a re-serialisation.
/// Every message is authenticated with HMAC-SHA256 under the device's own secret:
/// <c>sig = HMAC(secret, type|serial|seq|ts|nonce|body)</c>.
/// </summary>
public sealed record Envelope(
    [property: JsonPropertyName("t")] string Type,
    [property: JsonPropertyName("s")] string Serial,
    [property: JsonPropertyName("q")] long Seq,
    [property: JsonPropertyName("ts")] long TimestampMs,
    [property: JsonPropertyName("n")] string Nonce,
    [property: JsonPropertyName("b")] string Body,
    [property: JsonPropertyName("sig")] string Signature);

public static class MessageTypes
{
    public const string Hello = "hello";        // device -> cloud: {firmware}
    public const string Welcome = "welcome";    // cloud -> device: {deviceId}
    public const string Report = "report";      // device -> cloud: {state}
    public const string Heartbeat = "hb";       // device -> cloud: {}
    public const string Command = "cmd";        // cloud -> device: {id, action, args}
    public const string Ack = "ack";            // device -> cloud: {id, ok, error?, state?}
    public const string Reject = "reject";      // cloud -> device: {reason} then close
}

public enum EnvelopeCheck
{
    Ok,
    Malformed,
    WrongDevice,
    BadSignature,
    Stale,
    OutOfOrder,
}

public static class DeviceProtocol
{
    /// <summary>Maximum clock difference accepted between device and cloud.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);

    public const int MaxMessageBytes = 16 * 1024;

    public static Envelope Seal(byte[] secret, string type, string serial, long seq, long tsMs, object body)
    {
        var bodyJson = JsonSerializer.Serialize(body);
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
        return new Envelope(type, serial, seq, tsMs, nonce, bodyJson, Sign(secret, type, serial, seq, tsMs, nonce, bodyJson));
    }

    public static string Sign(byte[] secret, string type, string serial, long seq, long tsMs, string nonce, string body)
    {
        var canonical = string.Create(CultureInfo.InvariantCulture, $"{type}|{serial}|{seq}|{tsMs}|{nonce}|{body}");
        return Convert.ToHexString(HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(canonical)));
    }

    /// <summary>Checks authenticity, freshness and ordering. Replay of a fresh nonce is checked by the caller's nonce store.</summary>
    public static EnvelopeCheck Verify(Envelope e, byte[] secret, string expectedSerial, long lastSeq, long nowMs)
    {
        if (e.Signature.Length != 64 || e.Nonce.Length is < 16 or > 64)
        {
            return EnvelopeCheck.Malformed;
        }

        if (!string.Equals(e.Serial, expectedSerial, StringComparison.Ordinal))
        {
            return EnvelopeCheck.WrongDevice;
        }

        var expected = Sign(secret, e.Type, e.Serial, e.Seq, e.TimestampMs, e.Nonce, e.Body);
        byte[] given;
        try
        {
            given = Convert.FromHexString(e.Signature);
        }
        catch (FormatException)
        {
            return EnvelopeCheck.Malformed;
        }

        if (!CryptographicOperations.FixedTimeEquals(given, Convert.FromHexString(expected)))
        {
            return EnvelopeCheck.BadSignature;
        }

        if (Math.Abs(nowMs - e.TimestampMs) > ClockSkew.TotalMilliseconds)
        {
            return EnvelopeCheck.Stale;
        }

        return e.Seq <= lastSeq ? EnvelopeCheck.OutOfOrder : EnvelopeCheck.Ok;
    }

    public static string Serialize(Envelope e) => JsonSerializer.Serialize(e);

    public static Envelope? Parse(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<Envelope>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Compares dotted firmware versions numerically ("1.10.0" &gt; "1.9.3").</summary>
    public static int CompareVersions(string a, string b)
    {
        var pa = a.Split('.');
        var pb = b.Split('.');
        for (var i = 0; i < Math.Max(pa.Length, pb.Length); i++)
        {
            var x = i < pa.Length && int.TryParse(pa[i], CultureInfo.InvariantCulture, out var vx) ? vx : 0;
            var y = i < pb.Length && int.TryParse(pb[i], CultureInfo.InvariantCulture, out var vy) ? vy : 0;
            if (x != y)
            {
                return x.CompareTo(y);
            }
        }

        return 0;
    }
}
