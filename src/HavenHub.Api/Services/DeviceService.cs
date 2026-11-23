using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using HavenHub.Core;
using HavenHub.Core.Devices;
using HavenHub.Core.Protocol;
using HavenHub.Core.Security;
using HavenHub.Data;

namespace HavenHub.Api.Services;

public sealed record PairResult(long DeviceId, string Secret);

/// <summary>Device pairing and the handling of state reports.</summary>
public sealed partial class DeviceService(Database db, IClock clock, HavenHubOptions options, SecretBox box, EventHub hub, SecurityService security)
{
    public const int MaxStateKeys = 32;

    public enum PairError
    {
        None,
        InvalidCode,
        BadSerial,
        SerialTaken,
        FirmwareTooOld,
    }

    public string CreatePairingCode(long homeId, long userId, DeviceKind kind, string name, Zone? zone)
    {
        var code = PairingCode.New();
        var now = clock.NowMs;
        db.Transaction(c =>
        {
            DeviceRepository.AddPairingCode(c, PairingCode.Digest(code), homeId, kind, name, zone ?? DeviceType.For(kind).DefaultZone, now + (options.PairingCodeMinutes * 60_000L));
            AuditRepository.Append(c, userId, homeId, "pairing_code_created", $"{kind} '{name}'", now);
        });
        return code;
    }

    /// <summary>
    /// Exchanges a one-time pairing code for a device identity. The device gets a fresh random 256-bit
    /// secret exactly once; the cloud keeps it only encrypted (AES-GCM), so there are no shared or
    /// default credentials (ETSI EN 303 645 provision 5.1).
    /// </summary>
    public (PairError Error, PairResult? Result) Pair(string code, string serial, string firmware)
    {
        if (!SerialPattern().IsMatch(serial))
        {
            return (PairError.BadSerial, null);
        }

        if (DeviceProtocol.CompareVersions(firmware, options.MinimumFirmware) < 0)
        {
            return (PairError.FirmwareTooOld, null);
        }

        var now = clock.NowMs;
        var secret = RandomNumberGenerator.GetBytes(32);
        var sealedSecret = box.Seal(secret, "device:" + serial);
        var outcome = db.Transaction(c =>
        {
            if (DeviceRepository.BySerial(c, serial) is not null)
            {
                return (PairError.SerialTaken, 0L, 0L);
            }

            var claim = DeviceRepository.ClaimPairingCode(c, PairingCode.Digest(code), now);
            if (claim is null)
            {
                return (PairError.InvalidCode, 0L, 0L);
            }

            var id = DeviceRepository.Create(c, claim.HomeId, claim.Kind, claim.Name, claim.Zone, serial, sealedSecret, firmware, now);
            EventRepository.Add(c, claim.HomeId, id, "device_paired", claim.Name, now);
            AuditRepository.Append(c, null, claim.HomeId, "device_paired", $"{claim.Kind} '{claim.Name}' serial {serial}", now);
            return (PairError.None, id, claim.HomeId);
        });

        if (outcome.Item1 != PairError.None)
        {
            return (outcome.Item1, null);
        }

        hub.Publish(outcome.Item3, "device_paired", new { deviceId = outcome.Item2 });
        return (PairError.None, new PairResult(outcome.Item2, Convert.ToBase64String(secret)));
    }

    public byte[] SecretFor(Device device) => box.Open(device.SecretEnc, "device:" + device.Serial);

    /// <summary>
    /// Merges a partial state report into the device's stored state, works out what changed
    /// (door opened, motion, low battery...) and passes each signal to the security panel, all in one
    /// transaction so the history, the device state and the alarm state never disagree.
    /// </summary>
    public IReadOnlyList<SignalType> ApplyReport(long deviceId, JsonObject partial)
    {
        if (partial.Count > MaxStateKeys)
        {
            throw new ArgumentException("too many state keys", nameof(partial));
        }

        var now = clock.NowMs;
        var (homeId, merged, signals, panels) = db.Transaction(c =>
        {
            var device = DeviceRepository.ById(c, deviceId) ?? throw new InvalidOperationException("device was removed");
            var previous = JsonNode.Parse(device.StateJson) as JsonObject ?? [];
            var next = (JsonObject)previous.DeepClone();
            foreach (var (key, value) in partial)
            {
                next[key] = value?.DeepClone();
            }

            var found = DeviceType.For(device.Kind).Interpret(previous, next).ToList();
            DeviceRepository.SaveState(c, deviceId, next.ToJsonString(), now);
            var results = new List<Core.Security.PanelResult>();
            foreach (var signal in found)
            {
                EventRepository.Add(c, device.HomeId, deviceId, "device:" + signal, device.Name, now);
                results.Add(security.ApplySignal(c, device.HomeId, deviceId, signal, device.Zone, now));
            }

            return (device.HomeId, next, found, results);
        });

        hub.Publish(homeId, "device_state", new { deviceId, state = merged, signals });
        foreach (var r in panels)
        {
            security.Announce(homeId, r);
        }

        return signals;
    }

    [GeneratedRegex("^[A-Za-z0-9-]{6,40}$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex SerialPattern();
}
