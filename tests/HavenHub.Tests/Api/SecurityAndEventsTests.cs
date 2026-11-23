using System.Net;
using System.Text.Json.Nodes;
using HavenHub.Core.Devices;
using HavenHub.Data;
using HavenHub.Tests.Framework;
using static HavenHub.Tests.Api.TestServer;

namespace HavenHub.Tests.Api;

public sealed class SecurityAndEventsTests
{
    private static async Task<string> Alarm(HavenHub.DeviceSim.HavenHubClient api, long home) =>
        (await api.GetAsync($"/api/homes/{home}/security")).Body!["alarm"]!.GetValue<string>();

    [Test("REQ-13", "REQ-15")]
    public async Task A_break_in_while_armed_away_sounds_the_alarm_after_the_entry_delay()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var door = await s.DeviceAsync(api, home, DeviceKind.ContactSensor, "Front door");

        Status(HttpStatusCode.OK, await api.PostAsync($"/api/homes/{home}/security/arm", new { mode = "ArmedAway", bypass = false }), "arm away");
        Assert.Equal("ExitDelay", await Alarm(api, home));
        s.Clock.Advance(TimeSpan.FromSeconds(61));
        s.Housekeep();
        Assert.Equal("Idle", await Alarm(api, home), "armed and settled");

        await door.ReportAsync(new JsonObject { ["open"] = true });
        await WaitUntil(() => s.Db.Read(c => HomeRepository.ById(c, home))!.Panel.Alarm == Core.Security.AlarmState.EntryDelay, "entry delay");
        s.Clock.Advance(TimeSpan.FromSeconds(29));
        s.Housekeep();
        Assert.Equal("EntryDelay", await Alarm(api, home), "still counting");
        s.Clock.Advance(TimeSpan.FromSeconds(2));
        s.Housekeep();
        Assert.Equal("Triggered", await Alarm(api, home));

        var types = (await api.GetAsync($"/api/homes/{home}/events?limit=10")).Body!["items"]!.AsArray().Select(e => e!["type"]!.GetValue<string>()).ToList();
        Assert.Equal("panel:alarm_triggered:entry_timeout", types[0]);
        Assert.True(types.Contains("device:ContactOpened") && types.Contains("panel:entry_delay_started"), "history explains the alarm");
    }

    [Test("REQ-13")]
    public async Task Arming_with_a_door_open_is_refused_unless_the_user_bypasses_it()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var window = await s.DeviceAsync(api, home, DeviceKind.ContactSensor, "Kitchen window");
        await window.ReportAsync(new JsonObject { ["open"] = true });
        await WaitUntil(() => s.DeviceState(window.DeviceId)["open"]!.GetValue<bool>(), "window open");

        var refused = await api.PostAsync($"/api/homes/{home}/security/arm", new { mode = "ArmedStay", bypass = false });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, refused.Status);
        Assert.Contains("Kitchen window", refused.Body!["error"]!.GetValue<string>());
        Status(HttpStatusCode.OK, await api.PostAsync($"/api/homes/{home}/security/arm", new { mode = "ArmedStay", bypass = true }), "bypass");
        Status(HttpStatusCode.Conflict, await api.PostAsync($"/api/homes/{home}/security/arm", new { mode = "ArmedAway", bypass = true }), "already armed");
    }

    [Test("REQ-13", "REQ-15")]
    public async Task Interior_motion_triggers_away_mode_immediately_and_tamper_triggers_any_armed_mode()
    {
        await using var s = await StartAsync(o => o.ExitDelaySeconds = 0);
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var hall = await s.DeviceAsync(api, home, DeviceKind.MotionSensor, "Hall");
        var lockDevice = await s.DeviceAsync(api, home, DeviceKind.Lock, "Door lock");
        await api.PostAsync($"/api/homes/{home}/security/arm", new { mode = "ArmedAway", bypass = false });
        s.Housekeep();
        await hall.ReportAsync(new JsonObject { ["motion"] = true });
        await WaitUntil(() => s.Db.Read(c => HomeRepository.ById(c, home))!.Panel.Alarm == Core.Security.AlarmState.Triggered, "motion alarm");

        await api.PostAsync($"/api/homes/{home}/security/disarm", new { pin = "2468" });
        await api.PostAsync($"/api/homes/{home}/security/arm", new { mode = "ArmedStay", bypass = false });
        await hall.ReportAsync(new JsonObject { ["motion"] = false });
        await hall.ReportAsync(new JsonObject { ["motion"] = true });
        await Task.Delay(150);
        Assert.Equal("Idle", await Alarm(api, home), "motion ignored in Stay");
        await lockDevice.ReportAsync(new JsonObject { ["tamper"] = true });
        await WaitUntil(() => s.Db.Read(c => HomeRepository.ById(c, home))!.Panel.Alarm == Core.Security.AlarmState.Triggered, "tamper alarm");
    }

    [Test("REQ-14")]
    public async Task Disarming_needs_the_pin_and_repeated_wrong_pins_lock_it()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync("7319");
        Status(HttpStatusCode.BadRequest, await api.PostAsync("/api/homes", new { name = "Weak", panelPin = "1234" }), "weak PIN refused at setup");
        await api.PostAsync($"/api/homes/{home}/security/arm", new { mode = "ArmedStay", bypass = false });
        for (var i = 0; i < 5; i++)
        {
            Status(HttpStatusCode.Forbidden, await api.PostAsync($"/api/homes/{home}/security/disarm", new { pin = "0000" }), "wrong PIN " + i);
        }

        Status(HttpStatusCode.TooManyRequests, await api.PostAsync($"/api/homes/{home}/security/disarm", new { pin = "7319" }), "locked even with the right PIN");
        Assert.True((await api.GetAsync($"/api/homes/{home}/security")).Body!["pinLocked"]!.GetValue<bool>(), "status shows lock");
        s.Clock.Advance(TimeSpan.FromMinutes(6));
        var ok = await api.PostAsync($"/api/homes/{home}/security/disarm", new { pin = "7319" });
        Assert.Equal("Disarmed", ok.Body!["mode"]!.GetValue<string>());
        Assert.True(s.Db.Read(c => c.Scalar("SELECT COUNT(*) AS v FROM audit_log WHERE action = 'disarm_failed'")) == 5, "failures audited");
    }

    [Test("REQ-16")]
    public async Task Event_history_pages_newest_first()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var bell = await s.DeviceAsync(api, home, DeviceKind.Doorbell);
        for (var i = 1; i <= 12; i++)
        {
            s.Clock.Advance(TimeSpan.FromSeconds(1));
            await bell.ReportAsync(new JsonObject { ["presses"] = i });
        }

        await WaitUntil(() => s.Db.Read(c => c.Scalar("SELECT COUNT(*) AS v FROM events WHERE type = 'device:DoorbellPressed'")) == 12, "12 rings");
        var ids = new List<long>();
        var path = $"/api/homes/{home}/events?limit=5";
        while (true)
        {
            var page = (await api.GetAsync(path)).Body!;
            ids.AddRange(page["items"]!.AsArray().Select(e => e!["id"]!.GetValue<long>()));
            if (page["next"] is not JsonObject next)
            {
                break;
            }

            path = $"/api/homes/{home}/events?limit=5&beforeAt={next["beforeAt"]}&beforeId={next["beforeId"]}";
        }

        Assert.Equal(ids.Count, ids.Distinct().Count(), "no repeats");
        Assert.True(ids.SequenceEqual(ids.OrderByDescending(x => x)), "newest first");
        Assert.Equal(s.Db.Read(c => c.Scalar($"SELECT COUNT(*) AS v FROM events WHERE home_id = {home}")), (long)ids.Count, "every event");
    }

    [Test("REQ-17")]
    public async Task Reports_summarise_activity_and_command_reliability()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var lamp = await s.DeviceAsync(api, home, DeviceKind.Light, "Lamp");
        await api.CommandAsync(home, lamp.DeviceId, "on");
        await api.CommandAsync(home, lamp.DeviceId, "off");
        lamp.Unresponsive = true;
        await api.CommandAsync(home, lamp.DeviceId, "on", wait: false);
        s.Clock.Advance(TimeSpan.FromSeconds(5));
        s.Housekeep();

        var report = (await api.GetAsync($"/api/homes/{home}/reports?days=7")).Body!;
        var row = report["commands"]!.AsArray().Single()!;
        Assert.Equal("Lamp", row["device"]!.GetValue<string>());
        Assert.Equal(3L, row["total"]!.GetValue<long>());
        Assert.Equal(2L, row["acked"]!.GetValue<long>());
        Assert.Equal(1L, row["failed"]!.GetValue<long>());
        Assert.True(report["daily"]!.AsArray().Any(d => d!["type"]!.GetValue<string>() == "device_online"), "daily activity");
    }

    [Test("REQ-18")]
    public async Task The_live_stream_pushes_device_and_panel_events()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var door = await s.DeviceAsync(api, home, DeviceKind.ContactSensor);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"/api/homes/{home}/stream", UriKind.Relative));
        using var response = await api.Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType?.MediaType);
        using var reader = new StreamReader(await response.Content.ReadAsStreamAsync());
        Assert.Equal(": connected", await reader.ReadLineAsync());

        await door.ReportAsync(new JsonObject { ["open"] = true });
        await WaitUntil(() => s.DeviceState(door.DeviceId)["open"]!.GetValue<bool>(), "report applied"); // device and API are separate connections
        await api.PostAsync($"/api/homes/{home}/security/arm", new { mode = "ArmedStay", bypass = true });
        var seen = new List<string>();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (seen.Count < 2)
        {
            var line = await reader.ReadLineAsync(timeout.Token);
            if (line?.StartsWith("data: ", StringComparison.Ordinal) == true)
            {
                seen.Add(JsonNode.Parse(line[6..])!["type"]!.GetValue<string>());
            }
        }

        Assert.Equal("device_state", seen[0]);
        Assert.Equal("panel", seen[1]);
    }

    [Test("REQ-19")]
    public async Task Security_actions_are_audited_in_an_intact_hash_chain()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var door = await s.DeviceAsync(api, home, DeviceKind.Lock);
        await api.CommandAsync(home, door.DeviceId, "unlock");
        await api.PostAsync($"/api/homes/{home}/security/arm", new { mode = "ArmedStay", bypass = false });
        await api.PostAsync($"/api/homes/{home}/security/disarm", new { pin = "2468" });

        var audit = (await api.GetAsync($"/api/homes/{home}/audit")).Body!;
        Assert.True(audit["chainIntact"]!.GetValue<bool>(), "chain intact");
        var actions = audit["entries"]!.AsArray().Select(e => e!["action"]!.GetValue<string>()).ToList();
        foreach (var expected in new[] { "home_created", "pairing_code_created", "device_paired", "command:unlock", "panel:armed_stay", "panel:disarmed" })
        {
            Assert.True(actions.Contains(expected), "audited: " + expected);
        }

        s.Db.Write(c => c.Execute("UPDATE audit_log SET detail = 'nothing to see' WHERE action = 'command:unlock'"));
        Assert.False((await api.GetAsync($"/api/homes/{home}/audit")).Body!["chainIntact"]!.GetValue<bool>(), "edit detected");
    }
}
