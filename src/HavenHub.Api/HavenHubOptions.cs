using System.Security.Cryptography;
using HavenHub.Core.Security;

namespace HavenHub.Api;

/// <summary>Service settings, bound from the "HavenHub" configuration section or HAVENHUB__* environment variables.</summary>
public sealed class HavenHubOptions
{
    public string DatabasePath { get; set; } = "havenhub.db";

    /// <summary>Base64 256-bit key that encrypts device secrets at rest. Required outside Development.</summary>
    public string? MasterKey { get; set; }

    /// <summary>Base64 key (at least 256 bits) that signs user tokens. Required outside Development.</summary>
    public string? TokenKey { get; set; }

    public int PasswordIterations { get; set; } = PasswordHasher.DefaultIterations;

    public int TokenLifetimeMinutes { get; set; } = 60;

    public int EntryDelaySeconds { get; set; } = 30;

    public int ExitDelaySeconds { get; set; } = 60;

    public int CommandAckTimeoutSeconds { get; set; } = 10;

    public int HeartbeatTimeoutSeconds { get; set; } = 90;

    public int PairingCodeMinutes { get; set; } = 10;

    /// <summary>Devices below this firmware are refused until updated (ETSI EN 303 645 provision 5.3).</summary>
    public string MinimumFirmware { get; set; } = "2.0.0";

    public int MaxLoginFailures { get; set; } = 5;

    public int LoginLockoutMinutes { get; set; } = 15;

    public int MaxPinFailures { get; set; } = 5;

    public int PinLockoutMinutes { get; set; } = 5;

    public int AuthRequestsPerMinute { get; set; } = 10;

    public int CommandsPerMinute { get; set; } = 120;

    public int PairRequestsPerMinute { get; set; } = 30;

    public int PinAttemptsPerMinute { get; set; } = 10;

    public int HousekeepingIntervalMs { get; set; } = 250;

    public PanelSettings Panel => new(TimeSpan.FromSeconds(EntryDelaySeconds), TimeSpan.FromSeconds(ExitDelaySeconds));

    public TimeSpan AckTimeout => TimeSpan.FromSeconds(CommandAckTimeoutSeconds);

    /// <summary>Decodes a configured key, or makes a throwaway one in Development so the service runs out of the box.</summary>
    public static byte[] ResolveKey(string? configured, string name, bool isDevelopment, int minBytes)
    {
        if (!string.IsNullOrWhiteSpace(configured))
        {
            var key = Convert.FromBase64String(configured);
            if (key.Length < minBytes)
            {
                throw new InvalidOperationException($"{name} must be at least {minBytes * 8} bits");
            }

            return key;
        }

        if (!isDevelopment)
        {
            throw new InvalidOperationException($"{name} is not configured. Set HavenHub__{name} to a base64 random key.");
        }

        return RandomNumberGenerator.GetBytes(32);
    }
}
