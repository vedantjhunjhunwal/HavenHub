using System.Security.Cryptography;
using System.Text.Json.Nodes;
using HavenHub.Core;
using HavenHub.Core.Devices;
using HavenHub.Core.Protocol;
using HavenHub.Core.Security;
using HavenHub.Tests.Framework;

namespace HavenHub.Tests.Unit;

public sealed class DeviceTypeTests
{
    private static List<SignalType> Signals(DeviceKind kind, JsonObject before, JsonObject after) =>
        DeviceType.For(kind).Interpret(before, after).ToList();

    [Test("REQ-09")]
    public void Unknown_actions_and_out_of_range_arguments_are_rejected()
    {
        var thermostat = DeviceType.For(DeviceKind.Thermostat);
        Assert.Equal("unsupported_action", thermostat.Check("unlock", [], []).Error);
        Assert.False(thermostat.Check("set_setpoint", new JsonObject { ["celsius"] = 45 }, []).Ok, "45 C");
        Assert.False(thermostat.Check("set_setpoint", new JsonObject { ["celsius"] = "warm" }, []).Ok, "non-number");
        Assert.True(thermostat.Check("set_setpoint", new JsonObject { ["celsius"] = 21.5 }, []).Ok, "21.5 C");
        Assert.False(thermostat.Check("set_mode", new JsonObject { ["mode"] = "turbo" }, []).Ok, "bad mode");
        Assert.False(DeviceType.For(DeviceKind.Light).Check("dim", new JsonObject { ["level"] = 0 }, []).Ok, "dim 0");
        Assert.Equal(0, DeviceType.For(DeviceKind.MotionSensor).Actions.Count, "sensors take no commands");
    }

    [Test("REQ-09")]
    public void Safety_interlocks_block_closing_on_an_obstruction_and_locking_a_jammed_bolt()
    {
        Assert.Equal("obstruction_detected", DeviceType.For(DeviceKind.GarageDoor).Check("close", [], new JsonObject { ["obstructed"] = true }).Error);
        Assert.True(DeviceType.For(DeviceKind.GarageDoor).Check("open", [], new JsonObject { ["obstructed"] = true }).Ok, "opening is still allowed");
        Assert.Equal("lock_jammed", DeviceType.For(DeviceKind.Lock).Check("lock", [], new JsonObject { ["jammed"] = true }).Error);
    }

    [Test("REQ-04", "REQ-09")]
    public void Guests_may_lock_and_adjust_comfort_devices_but_not_unlock_or_open_the_garage()
    {
        Assert.Equal(HomeRole.Guest, DeviceType.For(DeviceKind.Lock).MinimumRole("lock"));
        Assert.Equal(HomeRole.Member, DeviceType.For(DeviceKind.Lock).MinimumRole("unlock"));
        Assert.Equal(HomeRole.Member, DeviceType.For(DeviceKind.GarageDoor).MinimumRole("open"));
        Assert.Equal(HomeRole.Guest, DeviceType.For(DeviceKind.Light).MinimumRole("on"));
        Assert.Equal(HomeRole.Guest, DeviceType.For(DeviceKind.Thermostat).MinimumRole("set_setpoint"));
    }

    [Test("REQ-12")]
    public void Only_comfort_commands_may_wait_for_an_offline_device()
    {
        Assert.Equal(TimeSpan.Zero, DeviceType.For(DeviceKind.Lock).OfflineQueueTtl("unlock"));
        Assert.Equal(TimeSpan.Zero, DeviceType.For(DeviceKind.GarageDoor).OfflineQueueTtl("open"));
        Assert.Equal(TimeSpan.FromMinutes(5), DeviceType.For(DeviceKind.Light).OfflineQueueTtl("on"));
        Assert.Equal(TimeSpan.FromMinutes(5), DeviceType.For(DeviceKind.Thermostat).OfflineQueueTtl("set_mode"));
    }

    [Test("REQ-15")]
    public void Reports_become_signals_only_on_transitions()
    {
        Assert.Equal(SignalType.ContactOpened, Signals(DeviceKind.ContactSensor, new() { ["open"] = false }, new() { ["open"] = true }).Single());
        Assert.Equal(0, Signals(DeviceKind.ContactSensor, new() { ["open"] = true }, new() { ["open"] = true }).Count, "repeat report");
        Assert.Equal(SignalType.ContactClosed, Signals(DeviceKind.ContactSensor, new() { ["open"] = true }, new() { ["open"] = false }).Single());
        Assert.Equal(SignalType.Motion, Signals(DeviceKind.MotionSensor, new() { ["motion"] = false }, new() { ["motion"] = true }).Single());
        Assert.Equal(SignalType.Unlocked, Signals(DeviceKind.Lock, new() { ["locked"] = true }, new() { ["locked"] = false }).Single());
        Assert.Equal(SignalType.LockJammed, Signals(DeviceKind.Lock, new() { ["jammed"] = false }, new() { ["jammed"] = true }).Single());
        Assert.Equal(SignalType.GarageObstructed, Signals(DeviceKind.GarageDoor, [], new() { ["obstructed"] = true }).Single());
    }

    [Test("REQ-15")]
    public void Doorbell_counts_presses_and_battery_and_tamper_apply_to_every_device()
    {
        Assert.Equal(SignalType.DoorbellPressed, Signals(DeviceKind.Doorbell, new() { ["presses"] = 3 }, new() { ["presses"] = 5 }).Single());
        Assert.Equal(SignalType.LowBattery, Signals(DeviceKind.MotionSensor, new() { ["battery"] = 20 }, new() { ["battery"] = 14 }).Single());
        Assert.Equal(0, Signals(DeviceKind.MotionSensor, new() { ["battery"] = 14 }, new() { ["battery"] = 12 }).Count, "already low");
        Assert.Equal(SignalType.Tamper, Signals(DeviceKind.Lock, [], new() { ["tamper"] = true }).Single());
    }
}

public sealed class CryptoTests
{
    [Test("REQ-01", "REQ-14")]
    public void Password_hashes_are_salted_self_describing_and_verify_in_constant_time()
    {
        var a = PasswordHasher.Hash("correct horse battery", 1000);
        var b = PasswordHasher.Hash("correct horse battery", 1000);
        Assert.False(a == b, "salted");
        Assert.True(a.StartsWith("pbkdf2-sha256$1000$", StringComparison.Ordinal));
        Assert.True(PasswordHasher.Verify("correct horse battery", a));
        Assert.False(PasswordHasher.Verify("correct horse batterY", a));
        Assert.False(PasswordHasher.Verify("x", "not-a-hash"));
        Assert.Equal(600_000, PasswordHasher.DefaultIterations);
    }

    [Test("REQ-01", "REQ-14")]
    public void Credential_policy_rejects_short_common_and_weak_values()
    {
        Assert.Equal("password must be at least 12 characters", CredentialPolicy.PasswordProblem("short"));
        Assert.Equal("password is too common", CredentialPolicy.PasswordProblem("Password1234"));
        Assert.Equal(null, CredentialPolicy.PasswordProblem("a-much-longer-passphrase"));
        Assert.Equal("PIN is too easy to guess", CredentialPolicy.PinProblem("1234"));
        Assert.Equal("PIN must be 4 to 8 digits", CredentialPolicy.PinProblem("12a4"));
        Assert.Equal(null, CredentialPolicy.PinProblem("2468"));
    }

    [Test("REQ-03")]
    public void Tokens_expire_and_cannot_be_forged()
    {
        var clock = new ManualClock(DateTimeOffset.UnixEpoch.AddYears(56));
        var tokens = new TokenService(RandomNumberGenerator.GetBytes(32), clock, TimeSpan.FromMinutes(60));
        var token = tokens.Issue(42, 1);
        Assert.Equal(42L, tokens.Validate(token)!.UserId);

        var forged = TokenService.Base64Url("{\"UserId\":1,\"Version\":1,\"ExpiresMs\":99999999999999}"u8.ToArray()) + token[token.IndexOf('.', StringComparison.Ordinal)..];
        Assert.Equal(null, tokens.Validate(forged), "payload swapped");
        Assert.Equal(null, new TokenService(RandomNumberGenerator.GetBytes(32), clock, TimeSpan.FromMinutes(60)).Validate(token), "other key");
        Assert.Equal(null, tokens.Validate("garbage"), "garbage");
        clock.Advance(TimeSpan.FromMinutes(61));
        Assert.Equal(null, tokens.Validate(token), "expired");
    }

    [Test("REQ-06")]
    public void Secrets_at_rest_are_encrypted_and_bound_to_their_device()
    {
        var box = new SecretBox(RandomNumberGenerator.GetBytes(32));
        var secret = RandomNumberGenerator.GetBytes(32);
        var sealedBytes = box.Seal(secret, "device:LOCK-1");
        Assert.Equal(12 + 16 + 32, sealedBytes.Length);
        Assert.True(box.Open(sealedBytes, "device:LOCK-1").SequenceEqual(secret));
        Assert.Throws<AuthenticationTagMismatchException>(() => box.Open(sealedBytes, "device:LOCK-2"));
        sealedBytes[^1] ^= 1;
        Assert.Throws<AuthenticationTagMismatchException>(() => box.Open(sealedBytes, "device:LOCK-1"));
    }

    [Test("REQ-05")]
    public void Pairing_codes_are_random_unambiguous_and_stored_only_as_digests()
    {
        var codes = Enumerable.Range(0, 200).Select(_ => PairingCode.New()).ToList();
        Assert.Equal(200, codes.Distinct().Count());
        Assert.True(codes.All(c => c.Length == 10 && !c.Any(ch => "01OI".Contains(ch, StringComparison.Ordinal))), "no 0/1/O/I");
        Assert.Equal(PairingCode.Digest("abcd2345xy"), PairingCode.Digest(" ABCD2345XY "));
        Assert.Equal(64, PairingCode.Digest("ABCD2345XY").Length);
    }
}

public sealed class ProtocolTests
{
    private static readonly byte[] Secret = RandomNumberGenerator.GetBytes(32);
    private const long Now = 1_800_000_000_000;

    [Test("REQ-07")]
    public void Signed_messages_verify_and_any_change_is_detected()
    {
        var e = DeviceProtocol.Seal(Secret, MessageTypes.Report, "SENSOR-1", 5, Now, new { state = new { open = true } });
        Assert.Equal(EnvelopeCheck.Ok, DeviceProtocol.Verify(e, Secret, "SENSOR-1", 4, Now));
        Assert.Equal(EnvelopeCheck.BadSignature, DeviceProtocol.Verify(e with { Body = "{\"state\":{\"open\":false}}" }, Secret, "SENSOR-1", 4, Now), "body edited");
        Assert.Equal(EnvelopeCheck.BadSignature, DeviceProtocol.Verify(e with { Type = MessageTypes.Ack }, Secret, "SENSOR-1", 4, Now), "type edited");
        Assert.Equal(EnvelopeCheck.BadSignature, DeviceProtocol.Verify(e, RandomNumberGenerator.GetBytes(32), "SENSOR-1", 4, Now), "wrong key");
        Assert.Equal(EnvelopeCheck.WrongDevice, DeviceProtocol.Verify(e, Secret, "SENSOR-2", 4, Now));
        Assert.Equal(EnvelopeCheck.Malformed, DeviceProtocol.Verify(e with { Signature = "zz" }, Secret, "SENSOR-1", 4, Now));
    }

    [Test("REQ-07")]
    public void Stale_and_out_of_order_messages_are_rejected()
    {
        var e = DeviceProtocol.Seal(Secret, MessageTypes.Heartbeat, "SENSOR-1", 5, Now, new { });
        Assert.Equal(EnvelopeCheck.Stale, DeviceProtocol.Verify(e, Secret, "SENSOR-1", 4, Now + 61_000), "61 s later");
        Assert.Equal(EnvelopeCheck.Ok, DeviceProtocol.Verify(e, Secret, "SENSOR-1", 4, Now + 59_000), "59 s later");
        Assert.Equal(EnvelopeCheck.OutOfOrder, DeviceProtocol.Verify(e, Secret, "SENSOR-1", 5, Now), "same seq");
    }

    [Test("REQ-08")]
    public void Firmware_versions_compare_numerically()
    {
        Assert.True(DeviceProtocol.CompareVersions("1.10.0", "1.9.3") > 0);
        Assert.True(DeviceProtocol.CompareVersions("2.0", "2.0.0") == 0);
        Assert.True(DeviceProtocol.CompareVersions("1.99.99", "2.0.0") < 0);
    }
}
