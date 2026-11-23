using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HavenHub.Core.Security;

/// <summary>PBKDF2-HMAC-SHA256 password and PIN hashing. The format stores its own iteration count.</summary>
public static class PasswordHasher
{
    public const int DefaultIterations = 600_000; // OWASP Password Storage guidance for PBKDF2-HMAC-SHA256
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    public static string Hash(string secret, int iterations = DefaultIterations)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Rfc2898DeriveBytes.Pbkdf2(secret, salt, iterations, HashAlgorithmName.SHA256, HashBytes);
        return string.Create(CultureInfo.InvariantCulture, $"pbkdf2-sha256${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}");
    }

    public static bool Verify(string secret, string stored)
    {
        var parts = stored.Split('$');
        if (parts.Length != 4 || parts[0] != "pbkdf2-sha256" || !int.TryParse(parts[1], CultureInfo.InvariantCulture, out var iterations))
        {
            return false;
        }

        var salt = Convert.FromBase64String(parts[2]);
        var expected = Convert.FromBase64String(parts[3]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(secret, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}

/// <summary>Rules for account passwords and panel PINs.</summary>
public static class CredentialPolicy
{
    // Small built-in deny list of the most common passwords (NIST SP 800-63B 5.1.1.2 asks for a blocklist).
    private static readonly HashSet<string> Common = new(StringComparer.OrdinalIgnoreCase)
    {
        "password1234", "123456789012", "qwertyuiop12", "letmein12345", "admin1234567", "welcome12345",
        "passw0rd1234", "iloveyou1234", "000000000000", "111111111111", "abc123456789", "changeme1234",
    };

    private static readonly HashSet<string> WeakPins = new(StringComparer.Ordinal)
    {
        "0000", "1111", "1234", "4321", "2580", "123456", "000000", "111111", "654321",
    };

    public static string? PasswordProblem(string password)
    {
        if (password.Length < 12)
        {
            return "password must be at least 12 characters";
        }

        if (password.Length > 128)
        {
            return "password must be at most 128 characters";
        }

        return Common.Contains(password) ? "password is too common" : null;
    }

    public static string? PinProblem(string pin)
    {
        if (pin.Length is < 4 or > 8 || !pin.All(char.IsAsciiDigit))
        {
            return "PIN must be 4 to 8 digits";
        }

        return WeakPins.Contains(pin) ? "PIN is too easy to guess" : null;
    }
}

/// <summary>
/// Signed bearer tokens: base64url(payload) + "." + base64url(HMAC-SHA256(key, payload)).
/// The payload carries the user id, expiry and the user's token version, so "sign out everywhere"
/// and account deletion invalidate every issued token.
/// </summary>
public sealed class TokenService
{
    private readonly byte[] _key;
    private readonly IClock _clock;
    private readonly TimeSpan _lifetime;

    public TokenService(byte[] key, IClock clock, TimeSpan lifetime)
    {
        if (key.Length < 32)
        {
            throw new ArgumentException("token key must be at least 256 bits", nameof(key));
        }

        _key = key;
        _clock = clock;
        _lifetime = lifetime;
    }

    public sealed record Claims(long UserId, int Version, long ExpiresMs);

    public string Issue(long userId, int version)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(new Claims(userId, version, _clock.NowMs + (long)_lifetime.TotalMilliseconds));
        return Base64Url(payload) + "." + Base64Url(HMACSHA256.HashData(_key, payload));
    }

    public Claims? Validate(string token)
    {
        var dot = token.IndexOf('.', StringComparison.Ordinal);
        if (dot <= 0)
        {
            return null;
        }

        try
        {
            var payload = FromBase64Url(token[..dot]);
            var sig = FromBase64Url(token[(dot + 1)..]);
            if (!CryptographicOperations.FixedTimeEquals(sig, HMACSHA256.HashData(_key, payload)))
            {
                return null;
            }

            var claims = JsonSerializer.Deserialize<Claims>(payload);
            return claims is not null && claims.ExpiresMs > _clock.NowMs ? claims : null;
        }
        catch (FormatException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static string Base64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromBase64Url(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t + new string('=', (4 - (t.Length % 4)) % 4));
    }
}

/// <summary>AES-256-GCM encryption for secrets at rest (device keys). Output: nonce | tag | ciphertext.</summary>
public sealed class SecretBox
{
    private readonly byte[] _key;

    public SecretBox(byte[] key)
    {
        if (key.Length != 32)
        {
            throw new ArgumentException("master key must be 256 bits", nameof(key));
        }

        _key = key;
    }

    public byte[] Seal(byte[] plaintext, string context)
    {
        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        var cipher = new byte[plaintext.Length];
        using var aes = new AesGcm(_key, tag.Length);
        aes.Encrypt(nonce, plaintext, cipher, tag, Encoding.UTF8.GetBytes(context));
        return [.. nonce, .. tag, .. cipher];
    }

    public byte[] Open(byte[] sealedBytes, string context)
    {
        var nonce = sealedBytes.AsSpan(0, 12);
        var tag = sealedBytes.AsSpan(12, 16);
        var cipher = sealedBytes.AsSpan(28);
        var plain = new byte[cipher.Length];
        using var aes = new AesGcm(_key, tag.Length);
        aes.Decrypt(nonce, cipher, tag, plain, Encoding.UTF8.GetBytes(context));
        return plain;
    }
}

/// <summary>Tamper-evident audit log: each entry's hash covers the previous entry's hash.</summary>
public static class AuditChain
{
    public const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

    public static string HashEntry(string previousHash, long atMs, long? userId, long? homeId, string action, string detail)
    {
        var canonical = string.Create(CultureInfo.InvariantCulture, $"{previousHash}|{atMs}|{userId}|{homeId}|{action}|{detail}");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}

/// <summary>Short-lived, single-use device pairing codes. Only their SHA-256 is stored.</summary>
public static class PairingCode
{
    private const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O or 1/I

    public static string New() => RandomNumberGenerator.GetString(Alphabet, 10);

    public static string Digest(string code) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code.Trim().ToUpperInvariant())));
}
