using System.Net;
using System.Text.Json.Nodes;
using HavenHub.Core.Devices;
using HavenHub.Core.Protocol;
using HavenHub.Data;
using HavenHub.DeviceSim;
using HavenHub.Tests.Framework;
using static HavenHub.Tests.Api.TestServer;

namespace HavenHub.Tests.Api;

public sealed class DeviceAndCommandTests
{
    [Test("REQ-05")]
    public async Task Pairing_codes_work_once_and_each_device_gets_its_own_secret()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var code = (await api.PostAsync($"/api/homes/{home}/pairing-codes", new { kind = "Lock", name = "Front door" })).Body!["code"]!.GetValue<string>();
        using var anonymous = new HavenHubClient(s.BaseUri);
        var first = await anonymous.PostAsync("/device/pair", new { code, serial = "LOCK-000001", firmware = "2.0.0" });
        Status(HttpStatusCode.OK, first, "first use");
        Status(HttpStatusCode.Unauthorized, await anonymous.PostAsync("/device/pair", new { code, serial = "LOCK-000002", firmware = "2.0.0" }), "second use");
        Status(HttpStatusCode.Unauthorized, await anonymous.PostAsync("/device/pair", new { code = "AAAAAAAAAA", serial = "LOCK-000003", firmware = "2.0.0" }), "made-up code");

        var code2 = (await api.PostAsync($"/api/homes/{home}/pairing-codes", new { kind = "Lock", name = "Back door" })).Body!["code"]!.GetValue<string>();
        Status(HttpStatusCode.Conflict, await anonymous.PostAsync("/device/pair", new { code = code2, serial = "LOCK-000001", firmware = "2.0.0" }), "serial reuse");
        Status(HttpStatusCode.BadRequest, await anonymous.PostAsync("/device/pair", new { code = code2, serial = "bad serial!", firmware = "2.0.0" }), "bad serial");
        var second = await anonymous.PostAsync("/device/pair", new { code = code2, serial = "LOCK-000009", firmware = "2.0.0" });
        Assert.False(first.Body!["secret"]!.GetValue<string>() == second.Body!["secret"]!.GetValue<string>(), "unique secrets");
        Assert.Equal(32, Convert.FromBase64String(second.Body!["secret"]!.GetValue<string>()).Length, "256-bit secret");

        var expiring = (await api.PostAsync($"/api/homes/{home}/pairing-codes", new { kind = "Light", name = "Lamp" })).Body!["code"]!.GetValue<string>();
        s.Clock.Advance(TimeSpan.FromMinutes(11));
        Status(HttpStatusCode.Unauthorized, await anonymous.PostAsync("/device/pair", new { code = expiring, serial = "LAMP-000001", firmware = "2.0.0" }), "expired code");
    }

    [Test("REQ-06")]
    public async Task Device_secrets_are_never_stored_in_plain_text()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var device = await s.DeviceAsync(api, home, DeviceKind.Lock, connect: false);
        var stored = s.Db.Read(c => DeviceRepository.ById(c, s.Db.Read(c2 => c2.Scalar("SELECT MAX(id) AS v FROM devices"))))!.SecretEnc;
        Assert.Equal(60, stored.Length, "nonce + tag + 32-byte ciphertext");
        Assert.False(stored.AsSpan().IndexOf(device.Secret) >= 0, "secret bytes not present");
        var file = await File.ReadAllBytesAsync(s.Db.Path);
        Assert.False(file.AsSpan().IndexOf(device.Secret) >= 0, "secret not in database file");
    }

    [Test("REQ-08")]
    public async Task Outdated_firmware_is_refused_at_pairing_and_at_connection()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var code = (await api.PostAsync($"/api/homes/{home}/pairing-codes", new { kind = "Light", name = "Old lamp" })).Body!["code"]!.GetValue<string>();
        using var anonymous = new HavenHubClient(s.BaseUri);
        Status((HttpStatusCode)426, await anonymous.PostAsync("/device/pair", new { code, serial = "LAMP-OLD-01", firmware = "1.9.9" }), "pairing");

        var current = await s.DeviceAsync(api, home, DeviceKind.Light, connect: false);
        await using var downgraded = new SimDevice(DeviceKind.Light, current.Serial, current.Secret, "1.4.0", s.Now);
        await downgraded.ConnectAsync(api.DeviceSocketUri);
        await WaitUntil(() => downgraded.CloseReason is not null, "refused");
        Assert.Equal("firmware_update_required", downgraded.CloseReason);
    }

    [Test("REQ-07")]
    public async Task Devices_with_the_wrong_secret_cannot_connect()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var real = await s.DeviceAsync(api, home, DeviceKind.Lock, connect: false);
        await using var impostor = new SimDevice(DeviceKind.Lock, real.Serial, new byte[32], "2.1.0", s.Now);
        await impostor.ConnectAsync(api.DeviceSocketUri);
        await WaitUntil(() => impostor.CloseReason is not null, "refused");
        Assert.Equal("hello_BADSIGNATURE", impostor.CloseReason);

        await using var unknown = new SimDevice(DeviceKind.Lock, "NOT-PAIRED-1", new byte[32], "2.1.0", s.Now);
        await unknown.ConnectAsync(api.DeviceSocketUri);
        await WaitUntil(() => unknown.CloseReason is not null, "refused");
        Assert.Equal("unknown_device", unknown.CloseReason);
    }

    [Test("REQ-07")]
    public async Task Replayed_tampered_and_stale_reports_are_dropped()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var sensor = await s.DeviceAsync(api, home, DeviceKind.ContactSensor, "Back door");
        var before = s.Db.Read(c => DeviceRepository.ById(c, sensor.DeviceId))!.StateVersion;

        var open = sensor.Build(MessageTypes.Report, new { state = new { open = true } });
        await sensor.SendRawAsync(DeviceProtocol.Serialize(open));
        await WaitUntil(() => s.DeviceState(sensor.DeviceId)["open"]!.GetValue<bool>(), "genuine report applied");

        await sensor.SendRawAsync(DeviceProtocol.Serialize(open)); // exact replay
        var tampered = sensor.Build(MessageTypes.Report, new { state = new { open = false } }) with { Body = "{\"state\":{\"open\":false,\"tamper\":false,\"battery\":100}}" };
        await sensor.SendRawAsync(DeviceProtocol.Serialize(tampered));
        var stale = DeviceProtocol.Seal(sensor.Secret, MessageTypes.Report, sensor.Serial, 1_000_000, s.Now() - 120_000, new { state = new { open = false } });
        await sensor.SendRawAsync(DeviceProtocol.Serialize(stale));

        await sensor.HeartbeatAsync(); // a later genuine message proves the connection stayed up
        await WaitUntil(() => s.Db.Read(c => DeviceRepository.ById(c, sensor.DeviceId))!.LastSeenMs >= 0, "heartbeat");
        await Task.Delay(100);
        Assert.Equal(before + 1, s.Db.Read(c => DeviceRepository.ById(c, sensor.DeviceId))!.StateVersion, "only the genuine report was applied");
        Assert.True(s.DeviceState(sensor.DeviceId)["open"]!.GetValue<bool>(), "state not rolled back by forged reports");
    }

    [Test("REQ-10", "REQ-15", "REQ-07")]
    public async Task A_command_travels_to_the_device_and_its_ack_updates_status_and_state()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var thermostat = await s.DeviceAsync(api, home, DeviceKind.Thermostat);
        var (status, body) = await api.CommandAsync(home, thermostat.DeviceId, "set_setpoint", new { celsius = 23.5 });
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("Acked", body!["status"]!.GetValue<string>());
        Assert.Equal(23.5, thermostat.State["setpoint"]!.GetValue<double>(), "device applied it");
        Assert.Equal(23.5, s.DeviceState(thermostat.DeviceId)["setpoint"]!.GetValue<double>(), "cloud state updated from the ack");
        Assert.Equal(0, thermostat.RejectedFromCloud, "every cloud message verified on the device");
        var fetched = await api.GetAsync($"/api/homes/{home}/commands/{body["id"]}");
        Assert.Equal("Acked", fetched.Body!["status"]!.GetValue<string>());
    }

    [Test("REQ-09")]
    public async Task Invalid_and_unsafe_commands_are_refused_before_reaching_the_device()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var thermostat = await s.DeviceAsync(api, home, DeviceKind.Thermostat);
        var garage = await s.DeviceAsync(api, home, DeviceKind.GarageDoor);
        Status(HttpStatusCode.UnprocessableEntity, await api.CommandAsync(home, thermostat.DeviceId, "set_setpoint", new { celsius = 50 }), "50 C");
        Status(HttpStatusCode.UnprocessableEntity, await api.CommandAsync(home, thermostat.DeviceId, "unlock"), "wrong action");
        await garage.ReportAsync(new JsonObject { ["obstructed"] = true });
        await WaitUntil(() => s.DeviceState(garage.DeviceId)["obstructed"]!.GetValue<bool>(), "obstruction reported");
        var refused = await api.CommandAsync(home, garage.DeviceId, "close");
        Assert.Equal("obstruction_detected", refused.Body!["error"]!.GetValue<string>());
        Assert.Equal(0, thermostat.CommandsReceived + garage.CommandsReceived, "nothing was sent");
    }

    [Test("REQ-10")]
    public async Task An_unanswered_command_times_out_and_a_failed_one_reports_the_device_error()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var door = await s.DeviceAsync(api, home, DeviceKind.Lock);
        door.Unresponsive = true;
        var (status, body) = await api.CommandAsync(home, door.DeviceId, "unlock", wait: false);
        Assert.Equal(HttpStatusCode.Accepted, status);
        await WaitUntil(() => door.CommandsReceived == 1, "delivered");
        s.Clock.Advance(TimeSpan.FromSeconds(3));
        Assert.Equal(1, s.Housekeep().CommandsSwept);
        var after = await api.GetAsync($"/api/homes/{home}/commands/{body!["id"]}");
        Assert.Equal("TimedOut", after.Body!["status"]!.GetValue<string>());

        door.Unresponsive = false;
        await door.ReportAsync(new JsonObject { ["jammed"] = false });
        door.State["jammed"] = true; // the bolt jams after the cloud's last report
        var failed = await api.CommandAsync(home, door.DeviceId, "lock");
        Assert.Equal("Failed", failed.Body!["status"]!.GetValue<string>());
        Assert.Equal("bolt_jammed", failed.Body!["error"]!.GetValue<string>());
    }

    [Test("REQ-11")]
    public async Task Retrying_with_the_same_idempotency_key_never_runs_a_command_twice()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var door = await s.DeviceAsync(api, home, DeviceKind.Lock);
        var first = await api.CommandAsync(home, door.DeviceId, "unlock", key: "tap-42");
        var retry = await api.CommandAsync(home, door.DeviceId, "unlock", key: "tap-42");
        Assert.Equal(first.Body!["id"]!.GetValue<long>(), retry.Body!["id"]!.GetValue<long>(), "same command returned");
        Assert.Equal(1, door.CommandsReceived, "executed once");
        Status(HttpStatusCode.Conflict, await api.CommandAsync(home, door.DeviceId, "lock", key: "tap-42"), "key reused for another action");
    }

    [Test("REQ-12")]
    public async Task Comfort_commands_wait_for_an_offline_device_but_security_commands_fail_fast()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var lamp = await s.DeviceAsync(api, home, DeviceKind.Light);
        var door = await s.DeviceAsync(api, home, DeviceKind.Lock);
        await lamp.CloseAsync();
        await door.CloseAsync();
        await WaitUntil(() => !s.Db.Read(c => DeviceRepository.ById(c, lamp.DeviceId))!.Online && !s.Db.Read(c => DeviceRepository.ById(c, door.DeviceId))!.Online, "offline");

        var unlock = await api.CommandAsync(home, door.DeviceId, "unlock");
        Assert.Equal("Failed", unlock.Body!["status"]!.GetValue<string>());
        Assert.Equal("device_offline", unlock.Body!["error"]!.GetValue<string>());

        var on = await api.CommandAsync(home, lamp.DeviceId, "on", wait: false);
        Assert.Equal(HttpStatusCode.Accepted, on.Status);
        Assert.Equal("Pending", on.Body!["status"]!.GetValue<string>());
        var expires = await api.CommandAsync(home, lamp.DeviceId, "dim", new { level = 30 }, wait: false);

        await using var lampAgain = new SimDevice(DeviceKind.Light, lamp.Serial, lamp.Secret, "2.1.0", s.Now);
        s.Clock.Advance(TimeSpan.FromMinutes(1));
        await s.ConnectAsync(api, lampAgain);
        await WaitUntil(() => lampAgain.CommandsReceived == 2, "queued commands delivered on reconnect");
        await WaitUntil(() => s.Db.Read(c => CommandRepository.ById(c, on.Body["id"]!.GetValue<long>()))!.Status == CommandStatus.Acked, "acked");

        await lampAgain.CloseAsync();
        await WaitUntil(() => !s.Db.Read(c => DeviceRepository.ById(c, lamp.DeviceId))!.Online, "offline again");
        var late = await api.CommandAsync(home, lamp.DeviceId, "off", wait: false);
        s.Clock.Advance(TimeSpan.FromMinutes(6));
        s.Housekeep();
        Assert.Equal(CommandStatus.Expired, s.Db.Read(c => CommandRepository.ById(c, late.Body!["id"]!.GetValue<long>()))!.Status);
        Assert.Equal(CommandStatus.Acked, s.Db.Read(c => CommandRepository.ById(c, expires.Body!["id"]!.GetValue<long>()))!.Status, "delivered before expiry");
    }

    [Test("REQ-23")]
    public async Task A_device_that_stops_sending_heartbeats_is_marked_offline()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var sensor = await s.DeviceAsync(api, home, DeviceKind.MotionSensor);
        s.Clock.Advance(TimeSpan.FromSeconds(60));
        await sensor.HeartbeatAsync();
        await Task.Delay(100);
        s.Housekeep();
        Assert.True(s.Db.Read(c => DeviceRepository.ById(c, sensor.DeviceId))!.Online, "heartbeat keeps it online");
        s.Clock.Advance(TimeSpan.FromSeconds(91));
        s.Housekeep();
        await WaitUntil(() => !s.Db.Read(c => DeviceRepository.ById(c, sensor.DeviceId))!.Online, "marked offline");
        var events = await api.GetAsync($"/api/homes/{home}/events?limit=5");
        Assert.Equal("device_offline", events.Body!["items"]![0]!["type"]!.GetValue<string>());
    }
}
