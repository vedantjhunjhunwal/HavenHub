using System.Net;
using HavenHub.Core.Devices;
using HavenHub.Tests.Framework;
using static HavenHub.Tests.Api.TestServer;

namespace HavenHub.Tests.Api;

public sealed class AccountAndAccessTests
{
    [Test("REQ-01")]
    public async Task Registration_enforces_the_password_policy_and_unique_emails()
    {
        await using var s = await StartAsync();
        var api = s.Client();
        Status(HttpStatusCode.BadRequest, await api.PostAsync("/api/auth/register", new { email = "a@example.com", password = "short" }), "short password");
        Status(HttpStatusCode.BadRequest, await api.PostAsync("/api/auth/register", new { email = "a@example.com", password = "password1234" }), "common password");
        Status(HttpStatusCode.BadRequest, await api.PostAsync("/api/auth/register", new { email = "not-an-email", password = "a-long-enough-password" }), "bad email");
        Status(HttpStatusCode.Created, await api.PostAsync("/api/auth/register", new { email = "a@example.com", password = "a-long-enough-password" }), "valid");
        Status(HttpStatusCode.Conflict, await api.PostAsync("/api/auth/register", new { email = "A@Example.com", password = "a-long-enough-password" }), "duplicate");
        var stored = s.Db.Read(c => c.QuerySingle("SELECT password_hash FROM users", r => r.Text("password_hash")));
        Assert.True(stored!.StartsWith("pbkdf2-sha256$", StringComparison.Ordinal), "stored hashed");
    }

    [Test("REQ-02")]
    public async Task Five_wrong_passwords_lock_the_account_and_unknown_emails_look_the_same()
    {
        await using var s = await StartAsync();
        var api = s.Client();
        await api.PostAsync("/api/auth/register", new { email = "lock@example.com", password = "the-right-password" });
        var unknown = await api.PostAsync("/api/auth/login", new { email = "nobody@example.com", password = "whatever-password" });
        var wrong = await api.PostAsync("/api/auth/login", new { email = "lock@example.com", password = "the-wrong-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.Status);
        Assert.Equal(unknown.Body!.ToJsonString(), wrong.Body!.ToJsonString(), "same body");

        for (var i = 0; i < 4; i++)
        {
            await api.PostAsync("/api/auth/login", new { email = "lock@example.com", password = "the-wrong-password" });
        }

        Status(HttpStatusCode.TooManyRequests, await api.PostAsync("/api/auth/login", new { email = "lock@example.com", password = "the-right-password" }), "locked even with right password");
        s.Clock.Advance(TimeSpan.FromMinutes(16));
        Status(HttpStatusCode.OK, await api.PostAsync("/api/auth/login", new { email = "lock@example.com", password = "the-right-password" }), "after lockout");
    }

    [Test("REQ-03")]
    public async Task Tokens_are_required_expire_and_can_be_revoked_everywhere()
    {
        await using var s = await StartAsync();
        var anonymous = s.Client();
        Status(HttpStatusCode.Unauthorized, await anonymous.GetAsync("/api/homes"), "no token");
        anonymous.UseToken("forged.token");
        Status(HttpStatusCode.Unauthorized, await anonymous.GetAsync("/api/homes"), "forged token");

        var (api, _, _) = await s.OwnerWithHomeAsync();
        Status(HttpStatusCode.OK, await api.GetAsync("/api/homes"), "valid token");
        Status(HttpStatusCode.NoContent, await api.PostAsync("/api/me/logout-all"), "logout all");
        Status(HttpStatusCode.Unauthorized, await api.GetAsync("/api/homes"), "revoked token");

        var (api2, _, _) = await s.OwnerWithHomeAsync();
        s.Clock.Advance(TimeSpan.FromMinutes(61));
        Status(HttpStatusCode.Unauthorized, await api2.GetAsync("/api/homes"), "expired token");
    }

    [Test("REQ-04")]
    public async Task Non_members_get_404_for_everything_in_someone_elses_home()
    {
        await using var s = await StartAsync();
        var (owner, _, home) = await s.OwnerWithHomeAsync();
        var lamp = await s.DeviceAsync(owner, home, DeviceKind.Light);
        var (stranger, _, _) = await s.OwnerWithHomeAsync();

        foreach (var path in new[] { $"/api/homes/{home}", $"/api/homes/{home}/devices", $"/api/homes/{home}/security", $"/api/homes/{home}/events", $"/api/homes/{home}/audit" })
        {
            Status(HttpStatusCode.NotFound, await stranger.GetAsync(path), path);
        }

        Status(HttpStatusCode.NotFound, await stranger.CommandAsync(home, lamp.DeviceId, "on"), "command");
        Status(HttpStatusCode.NotFound, await stranger.PostAsync($"/api/homes/{home}/security/disarm", new { pin = "2468" }), "disarm");
        Status(HttpStatusCode.NotFound, await stranger.DeleteAsync($"/api/homes/{home}"), "delete");
        Status(HttpStatusCode.NotFound, await stranger.GetAsync($"/api/homes/999999"), "unknown home looks the same");

        // A device id from another home is refused even through the attacker's own home.
        var (_, _, strangerHome) = (stranger, 0, (await stranger.GetAsync("/api/homes")).Body![0]!["id"]!.GetValue<long>());
        Status(HttpStatusCode.NotFound, await stranger.CommandAsync(strangerHome, lamp.DeviceId, "on"), "cross-home device id");
    }

    [Test("REQ-04")]
    public async Task Guests_can_use_comfort_devices_but_not_unlock_arm_or_manage()
    {
        await using var s = await StartAsync();
        var (owner, _, home) = await s.OwnerWithHomeAsync();
        var lamp = await s.DeviceAsync(owner, home, DeviceKind.Light);
        var door = await s.DeviceAsync(owner, home, DeviceKind.Lock);
        var guest = s.Client();
        await guest.SignUpAsync("guest@example.com", "a-guest-password");
        Status(HttpStatusCode.OK, await owner.PostAsync($"/api/homes/{home}/members", new { email = "guest@example.com", role = "Guest" }), "invite guest");

        Assert.Equal("Acked", (await guest.CommandAsync(home, lamp.DeviceId, "on")).Body!["status"]!.GetValue<string>());
        Assert.Equal("Acked", (await guest.CommandAsync(home, door.DeviceId, "lock")).Body!["status"]!.GetValue<string>());
        Status(HttpStatusCode.Forbidden, await guest.CommandAsync(home, door.DeviceId, "unlock"), "guest unlock");
        Status(HttpStatusCode.Forbidden, await guest.PostAsync($"/api/homes/{home}/security/arm", new { mode = "ArmedAway", bypass = false }), "guest arm");
        Status(HttpStatusCode.Forbidden, await guest.PostAsync($"/api/homes/{home}/pairing-codes", new { kind = "Light", name = "x" }), "guest pairing");
        Status(HttpStatusCode.Forbidden, await guest.GetAsync($"/api/homes/{home}/audit"), "guest audit");
        Assert.Equal(1, door.CommandsReceived, "the refused unlock never reached the lock");
    }

    [Test("REQ-04")]
    public async Task A_home_always_keeps_an_owner()
    {
        await using var s = await StartAsync();
        var (owner, ownerId, home) = await s.OwnerWithHomeAsync();
        Status(HttpStatusCode.Conflict, await owner.DeleteAsync($"/api/homes/{home}/members/{ownerId}"), "remove last owner");
        Status(HttpStatusCode.NotFound, await owner.PostAsync($"/api/homes/{home}/members", new { email = "ghost@example.com", role = "Member" }), "unknown user");
    }

    [Test("REQ-20", "REQ-03")]
    public async Task Deleting_an_account_needs_the_password_and_removes_homes_it_alone_owned()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var lamp = await s.DeviceAsync(api, home, DeviceKind.Light);
        Status(HttpStatusCode.Forbidden, await api.DeleteAsync("/api/me", new { password = "wrong-password-here" }), "wrong password");
        Status(HttpStatusCode.NoContent, await api.DeleteAsync("/api/me", new { password = "a-long-test-password" }), "delete account");
        Status(HttpStatusCode.Unauthorized, await api.GetAsync("/api/homes"), "token dead");
        Assert.Equal(0L, s.Db.Read(c => c.Scalar("SELECT COUNT(*) AS v FROM homes")), "home removed");
        Assert.Equal(0L, s.Db.Read(c => c.Scalar("SELECT COUNT(*) AS v FROM devices")), "devices removed");
        await WaitUntil(() => lamp.CloseReason is not null, "device disconnected");
    }

    [Test("REQ-20")]
    public async Task Deleting_a_home_disconnects_its_devices_and_removes_its_data()
    {
        await using var s = await StartAsync();
        var (api, _, home) = await s.OwnerWithHomeAsync();
        var lamp = await s.DeviceAsync(api, home, DeviceKind.Light);
        await api.CommandAsync(home, lamp.DeviceId, "on");
        Status(HttpStatusCode.NoContent, await api.DeleteAsync($"/api/homes/{home}"), "delete home");
        await WaitUntil(() => lamp.CloseReason is not null, "device disconnected");
        foreach (var table in new[] { "homes", "devices", "commands", "events" })
        {
            Assert.Equal(0L, s.Db.Read(c => c.Scalar($"SELECT COUNT(*) AS v FROM {table}")), table);
        }

        Assert.True(s.Db.Read(c => c.Scalar("SELECT COUNT(*) AS v FROM audit_log WHERE action = 'home_deleted'")) == 1, "deletion audited");
    }

    [Test("REQ-21")]
    public async Task Login_attempts_are_rate_limited_per_client()
    {
        await using var s = await StartAsync(o => o.AuthRequestsPerMinute = 3);
        var api = s.Client();
        var codes = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++)
        {
            codes.Add((await api.PostAsync("/api/auth/login", new { email = "x@example.com", password = "whatever-password" })).Status);
        }

        Assert.Equal(3, codes.Count(c => c == HttpStatusCode.Unauthorized), "first three answered");
        Assert.Equal(2, codes.Count(c => c == HttpStatusCode.TooManyRequests), "then throttled");
    }

    [Test("REQ-21")]
    public async Task Pin_attempts_have_their_own_rate_limit_bucket()
    {
        await using var s = await StartAsync(o =>
        {
            o.AuthRequestsPerMinute = 2;
            o.PinAttemptsPerMinute = 2;
        });
        var (api, _, home) = await s.OwnerWithHomeAsync(); // uses the 2 auth requests
        Status(HttpStatusCode.Forbidden, await api.PostAsync($"/api/homes/{home}/security/disarm", new { pin = "9753" }), "first PIN attempt still allowed");
        Status(HttpStatusCode.OK, await api.PostAsync($"/api/homes/{home}/security/disarm", new { pin = "2468" }), "second PIN attempt");
        Status(HttpStatusCode.TooManyRequests, await api.PostAsync($"/api/homes/{home}/security/disarm", new { pin = "2468" }), "third throttled");
    }

    [Test("REQ-22")]
    public async Task Responses_carry_security_headers_and_large_bodies_are_refused()
    {
        await using var s = await StartAsync();
        var api = s.Client();
        using var response = await api.Http.GetAsync(new Uri("/api/homes", UriKind.Relative));
        string H(string name) => response.Headers.TryGetValues(name, out var v) ? string.Join(",", v) : "";
        Assert.Contains("default-src 'self'", H("Content-Security-Policy"));
        Assert.Contains("frame-ancestors 'none'", H("Content-Security-Policy"));
        Assert.Equal("nosniff", H("X-Content-Type-Options"));
        Assert.Equal("DENY", H("X-Frame-Options"));
        Assert.Equal("no-referrer", H("Referrer-Policy"));
        Assert.Equal("no-store", H("Cache-Control"));
        Assert.False(response.Headers.Contains("Server"), "no server banner");

        var big = new string('x', 100 * 1024);
        var tooBig = await api.PostAsync("/api/auth/register", new { email = "big@example.com", password = big });
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, tooBig.Status, "100 KB body");
    }

    [Test("REQ-25", "REQ-22")]
    public async Task Dashboard_is_html5_with_no_inline_code()
    {
        await using var s = await StartAsync();
        var html = await s.Client().Http.GetStringAsync(new Uri("/", UriKind.Relative));
        Assert.True(html.StartsWith("<!DOCTYPE html>", StringComparison.Ordinal), "HTML5 doctype");
        Assert.Contains("<script src=\"app.js\" defer></script>", html);
        Assert.False(System.Text.RegularExpressions.Regex.IsMatch(html, @"<script(?![^>]*\bsrc=)[^>]*>"), "no inline <script>");
        Assert.False(html.Contains(" style=", StringComparison.Ordinal) || html.Contains(" onclick=", StringComparison.Ordinal), "no inline style or handlers");
        var js = await s.Client().Http.GetStringAsync(new Uri("/app.js", UriKind.Relative));
        Assert.False(js.Contains(".innerHTML", StringComparison.Ordinal), "no innerHTML in dashboard script");
    }

    [Test("REQ-24")]
    public async Task Sql_in_user_input_is_stored_as_plain_text()
    {
        await using var s = await StartAsync();
        var (api, _, _) = await s.OwnerWithHomeAsync();
        var name = "x'); DELETE FROM homes; --";
        var id = await api.CreateHomeAsync(name, "8642");
        Assert.Equal(name, (await api.GetAsync($"/api/homes/{id}")).Body!["name"]!.GetValue<string>());
        Assert.Equal(2L, s.Db.Read(c => c.Scalar("SELECT COUNT(*) AS v FROM homes")));
    }
}
