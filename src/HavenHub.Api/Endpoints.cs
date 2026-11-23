using System.Text.Json;
using System.Text.Json.Nodes;
using HavenHub.Api.Infrastructure;
using HavenHub.Api.Services;
using HavenHub.Core;
using HavenHub.Core.Devices;
using HavenHub.Core.Security;
using HavenHub.Data;
using HavenHub.Data.Sqlite;
using Microsoft.AspNetCore.Mvc;

namespace HavenHub.Api;

public sealed record Credentials(string Email, string Password);

public sealed record CreateHomeRequest(string Name, string PanelPin);

public sealed record AddMemberRequest(string Email, HomeRole Role);

public sealed record PairingCodeRequest(DeviceKind Kind, string Name, Zone? Zone);

public sealed record PairRequest(string Code, string Serial, string Firmware);

public sealed record ArmRequest(ArmMode Mode, bool Bypass);

public sealed record DisarmRequest(string Pin);

public sealed record DeleteAccountRequest(string Password);

/// <summary>REST API. Every /api route except register and login requires a bearer token.</summary>
public static class Endpoints
{
    public static void Map(WebApplication app)
    {
        app.MapGet("/health", (Database db) => Results.Ok(new
        {
            status = "ok",
            sqlite = SqliteConnection.LibraryVersion,
            schema = db.Read(c => c.Scalar("SELECT MAX(version) AS v FROM schema_migrations")),
        }));

        var auth = app.MapGroup("/api/auth").RequireRateLimiting("auth");
        auth.MapPost("/register", Register);
        auth.MapPost("/login", Login);

        var api = app.MapGroup("/api").RequireAuthorization();
        api.MapGet("/me", Me);
        api.MapPost("/me/logout-all", LogoutAll);
        api.MapDelete("/me", DeleteAccount).RequireRateLimiting("auth");

        api.MapGet("/homes", (HttpContext http, Database db) =>
            Results.Ok(db.Read(c => HomeRepository.ForUser(c, http.UserId())).Select(m => new { id = m.HomeId, name = m.HomeName, m.Role })));
        api.MapPost("/homes", CreateHome);
        api.MapGet("/homes/{homeId:long}", GetHome);
        api.MapDelete("/homes/{homeId:long}", DeleteHome);
        api.MapPost("/homes/{homeId:long}/members", AddMember);
        api.MapDelete("/homes/{homeId:long}/members/{userId:long}", RemoveMember);

        api.MapPost("/homes/{homeId:long}/pairing-codes", CreatePairingCode);
        api.MapGet("/homes/{homeId:long}/devices", ListDevices);
        api.MapDelete("/homes/{homeId:long}/devices/{deviceId:long}", RemoveDevice);
        api.MapPost("/homes/{homeId:long}/devices/{deviceId:long}/commands", SendCommand).RequireRateLimiting("commands");
        api.MapGet("/homes/{homeId:long}/commands/{commandId:long}", GetCommand);

        api.MapGet("/homes/{homeId:long}/security", SecurityStatus);
        api.MapPost("/homes/{homeId:long}/security/arm", Arm);
        api.MapPost("/homes/{homeId:long}/security/disarm", Disarm).RequireRateLimiting("pin");

        api.MapGet("/homes/{homeId:long}/events", Events);
        api.MapGet("/homes/{homeId:long}/stream", Stream);
        api.MapGet("/homes/{homeId:long}/reports", Reports);
        api.MapGet("/homes/{homeId:long}/audit", Audit);

        app.MapPost("/device/pair", Pair).RequireRateLimiting("pairing");
        app.Map("/device/ws", (HttpContext http, DeviceGateway gateway) => gateway.HandleAsync(http));
    }

    private static IResult Register(Credentials body, Database db, IClock clock, HavenHubOptions options)
    {
        var email = body.Email?.Trim() ?? "";
        if (email.Length is < 3 or > 254 || !email.Contains('@', StringComparison.Ordinal))
        {
            return ApiError.BadRequest("invalid email");
        }

        if (CredentialPolicy.PasswordProblem(body.Password ?? "") is { } problem)
        {
            return ApiError.BadRequest(problem);
        }

        var hash = PasswordHasher.Hash(body.Password!, options.PasswordIterations);
        try
        {
            var id = db.Transaction(c =>
            {
                var userId = UserRepository.Create(c, email, hash, clock.NowMs);
                AuditRepository.Append(c, userId, null, "user_registered", "", clock.NowMs);
                return userId;
            });
            return Results.Created($"/api/me", new { id, email });
        }
        catch (DbException e) when (e.IsConstraint)
        {
            return ApiError.Conflict("email already registered");
        }
    }

    private static IResult Login(Credentials body, Database db, IClock clock, HavenHubOptions options, TokenService tokens)
    {
        var now = clock.NowMs;
        var user = db.Read(c => UserRepository.ByEmail(c, body.Email?.Trim() ?? ""));
        if (user is null)
        {
            // Same work and same answer as a wrong password, so login cannot be used to find accounts.
            PasswordHasher.Verify(body.Password ?? "", PasswordHasher.Hash("timing-equaliser", options.PasswordIterations));
            return ApiError.Unauthorized("invalid email or password");
        }

        if (user.LockedUntilMs > now)
        {
            return ApiError.TooMany("account temporarily locked after repeated failures");
        }

        if (!PasswordHasher.Verify(body.Password ?? "", user.PasswordHash))
        {
            db.Transaction(c =>
            {
                UserRepository.RecordLoginFailure(c, user.Id, options.MaxLoginFailures, now + (options.LoginLockoutMinutes * 60_000L));
                AuditRepository.Append(c, user.Id, null, "login_failed", "", now);
            });
            return ApiError.Unauthorized("invalid email or password");
        }

        db.Transaction(c =>
        {
            UserRepository.RecordLoginSuccess(c, user.Id);
            AuditRepository.Append(c, user.Id, null, "login", "", now);
        });
        return Results.Ok(new { token = tokens.Issue(user.Id, user.TokenVersion), expiresInMinutes = options.TokenLifetimeMinutes });
    }

    private static IResult Me(HttpContext http, Database db)
    {
        var user = db.Read(c => UserRepository.ById(c, http.UserId()))!;
        return Results.Ok(new { user.Id, user.Email });
    }

    private static IResult LogoutAll(HttpContext http, Database db, IClock clock)
    {
        db.Transaction(c =>
        {
            UserRepository.RevokeTokens(c, http.UserId());
            AuditRepository.Append(c, http.UserId(), null, "logout_all", "", clock.NowMs);
        });
        return Results.NoContent();
    }

    /// <summary>Deletes the account, its memberships and homes it alone owned (ETSI EN 303 645 provision 5.11).</summary>
    private static IResult DeleteAccount(HttpContext http, [FromBody] DeleteAccountRequest body, Database db, IClock clock, DeviceGateway gateway, EventHub hub)
    {
        var userId = http.UserId();
        var user = db.Read(c => UserRepository.ById(c, userId))!;
        if (!PasswordHasher.Verify(body.Password ?? "", user.PasswordHash))
        {
            return ApiError.Forbidden("password confirmation failed");
        }

        var owned = db.Read(c => HomeRepository.ForUser(c, userId));
        var removedHomes = db.Transaction(c =>
        {
            var before = owned.Select(m => m.HomeId).ToHashSet();
            UserRepository.Delete(c, userId);
            var orphans = before.Where(h => HomeRepository.OwnerCount(c, h) == 0).ToList();
            foreach (var homeId in orphans)
            {
                foreach (var d in DeviceRepository.ForHome(c, homeId))
                {
                    gateway.Disconnect(d.Id);
                }
            }

            HomeRepository.DeleteOrphans(c);
            AuditRepository.Append(c, null, null, "account_deleted", $"user {userId}; homes removed: {orphans.Count}", clock.NowMs);
            return orphans;
        });
        foreach (var homeId in removedHomes)
        {
            hub.Close(homeId);
        }

        return Results.NoContent();
    }

    private static IResult CreateHome(HttpContext http, CreateHomeRequest body, Database db, IClock clock, HavenHubOptions options)
    {
        var name = body.Name?.Trim() ?? "";
        if (name.Length is < 1 or > 80)
        {
            return ApiError.BadRequest("name must be 1 to 80 characters");
        }

        if (CredentialPolicy.PinProblem(body.PanelPin ?? "") is { } problem)
        {
            return ApiError.BadRequest(problem);
        }

        var pinHash = PasswordHasher.Hash(body.PanelPin!, options.PasswordIterations);
        var id = db.Transaction(c =>
        {
            var homeId = HomeRepository.Create(c, name, pinHash, http.UserId(), clock.NowMs);
            AuditRepository.Append(c, http.UserId(), homeId, "home_created", name, clock.NowMs);
            return homeId;
        });
        return Results.Created($"/api/homes/{id}", new { id, name });
    }

    private static IResult GetHome(HttpContext http, long homeId, Database db)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Guest, out var role) is { } denied)
        {
            return denied;
        }

        var home = db.Read(c => HomeRepository.ById(c, homeId))!;
        var members = role == HomeRole.Owner ? db.Read(c => HomeRepository.Members(c, homeId)).Select(m => new { m.UserId, m.Email, m.Role }) : null;
        return Results.Ok(new { home.Id, home.Name, yourRole = role, home.Panel.Mode, home.Panel.Alarm, members });
    }

    private static IResult DeleteHome(HttpContext http, long homeId, Database db, IClock clock, DeviceGateway gateway, EventHub hub)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Owner, out _) is { } denied)
        {
            return denied;
        }

        db.Transaction(c =>
        {
            foreach (var d in DeviceRepository.ForHome(c, homeId))
            {
                gateway.Disconnect(d.Id);
            }

            HomeRepository.Delete(c, homeId);
            AuditRepository.Append(c, http.UserId(), homeId, "home_deleted", "all devices, commands and events removed", clock.NowMs);
        });
        hub.Close(homeId);
        return Results.NoContent();
    }

    private static IResult AddMember(HttpContext http, long homeId, AddMemberRequest body, Database db, IClock clock)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Owner, out _) is { } denied)
        {
            return denied;
        }

        var user = db.Read(c => UserRepository.ByEmail(c, body.Email?.Trim() ?? ""));
        if (user is null)
        {
            return ApiError.NotFound("no account with that email");
        }

        db.Transaction(c =>
        {
            HomeRepository.AddMember(c, homeId, user.Id, body.Role);
            AuditRepository.Append(c, http.UserId(), homeId, "member_set", $"user {user.Id} as {body.Role}", clock.NowMs);
        });
        return Results.Ok(new { userId = user.Id, body.Role });
    }

    private static IResult RemoveMember(HttpContext http, long homeId, long userId, Database db, IClock clock)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Owner, out _) is { } denied)
        {
            return denied;
        }

        return db.Transaction(c =>
        {
            if (HomeRepository.RoleOf(c, homeId, userId) == HomeRole.Owner && HomeRepository.OwnerCount(c, homeId) == 1)
            {
                return ApiError.Conflict("a home must keep at least one owner");
            }

            if (HomeRepository.RemoveMember(c, homeId, userId) == 0)
            {
                return ApiError.NotFound("not a member");
            }

            AuditRepository.Append(c, http.UserId(), homeId, "member_removed", $"user {userId}", clock.NowMs);
            return Results.NoContent();
        });
    }

    private static IResult CreatePairingCode(HttpContext http, long homeId, PairingCodeRequest body, Database db, DeviceService devices, HavenHubOptions options)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Owner, out _) is { } denied)
        {
            return denied;
        }

        var name = body.Name?.Trim() ?? "";
        if (name.Length is < 1 or > 80)
        {
            return ApiError.BadRequest("name must be 1 to 80 characters");
        }

        var code = devices.CreatePairingCode(homeId, http.UserId(), body.Kind, name, body.Zone);
        return Results.Ok(new { code, expiresInMinutes = options.PairingCodeMinutes });
    }

    private static IResult Pair(PairRequest body, DeviceService devices) =>
        devices.Pair(body.Code ?? "", body.Serial ?? "", body.Firmware ?? "") switch
        {
            (DeviceService.PairError.None, var r) => Results.Ok(new { r!.DeviceId, r.Secret }),
            (DeviceService.PairError.BadSerial, _) => ApiError.BadRequest("serial must be 6-40 letters, digits or dashes"),
            (DeviceService.PairError.FirmwareTooOld, _) => ApiError.Error(StatusCodes.Status426UpgradeRequired, "firmware_update_required"),
            (DeviceService.PairError.SerialTaken, _) => ApiError.Conflict("serial already paired"),
            _ => ApiError.Unauthorized("invalid, used or expired pairing code"),
        };

    private static IResult ListDevices(HttpContext http, long homeId, Database db)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Guest, out _) is { } denied)
        {
            return denied;
        }

        return Results.Ok(db.Read(c => DeviceRepository.ForHome(c, homeId)).Select(d => new
        {
            d.Id,
            d.Name,
            d.Kind,
            d.Zone,
            d.Online,
            d.Firmware,
            d.LastSeenMs,
            state = JsonNode.Parse(d.StateJson),
            actions = DeviceType.For(d.Kind).Actions,
        }));
    }

    private static IResult RemoveDevice(HttpContext http, long homeId, long deviceId, Database db, IClock clock, DeviceGateway gateway)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Owner, out _) is { } denied)
        {
            return denied;
        }

        var device = db.Read(c => DeviceRepository.ById(c, deviceId));
        if (device is null || device.HomeId != homeId)
        {
            return ApiError.NotFound("device_not_found");
        }

        gateway.Disconnect(deviceId);
        db.Transaction(c =>
        {
            DeviceRepository.Delete(c, deviceId);
            AuditRepository.Append(c, http.UserId(), homeId, "device_removed", device.Name, clock.NowMs);
        });
        return Results.NoContent();
    }

    private static async Task<IResult> SendCommand(HttpContext http, long homeId, long deviceId, CommandRequest body, bool? wait, Database db, CommandService commands)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Guest, out var role) is { } denied)
        {
            return denied;
        }

        return string.IsNullOrWhiteSpace(body.Action)
            ? ApiError.BadRequest("action is required")
            : await commands.SubmitAsync(http.UserId(), homeId, deviceId, role, body, wait == true, http.RequestAborted);
    }

    private static IResult GetCommand(HttpContext http, long homeId, long commandId, Database db)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Guest, out _) is { } denied)
        {
            return denied;
        }

        var cmd = db.Read(c => CommandRepository.ById(c, commandId));
        return cmd is null || cmd.HomeId != homeId ? ApiError.NotFound("command_not_found") : Results.Ok(CommandService.Describe(cmd));
    }

    private static IResult SecurityStatus(HttpContext http, long homeId, Database db, SecurityService security) =>
        Access.Check(db, homeId, http.UserId(), HomeRole.Guest, out _) ?? Results.Ok(security.Status(homeId));

    private static IResult Arm(HttpContext http, long homeId, ArmRequest body, Database db, SecurityService security) =>
        Access.Check(db, homeId, http.UserId(), HomeRole.Member, out _) ?? security.Arm(homeId, http.UserId(), body.Mode, body.Bypass);

    private static IResult Disarm(HttpContext http, long homeId, DisarmRequest body, Database db, SecurityService security) =>
        Access.Check(db, homeId, http.UserId(), HomeRole.Member, out _) ?? security.Disarm(homeId, http.UserId(), body.Pin ?? "");

    private static IResult Events(HttpContext http, long homeId, long? beforeAt, long? beforeId, int? limit, Database db)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Guest, out _) is { } denied)
        {
            return denied;
        }

        var take = Math.Clamp(limit ?? 50, 1, 200);
        var rows = db.Read(c => EventRepository.Page(c, homeId, beforeAt, beforeId, take));
        var next = rows.Count == take ? new { beforeAt = rows[^1].AtMs, beforeId = rows[^1].Id } : null;
        return Results.Ok(new { items = rows.Select(e => new { e.Id, e.DeviceId, e.Type, e.Detail, at = e.AtMs }), next });
    }

    private static IResult Reports(HttpContext http, long homeId, int? days, Database db, IClock clock)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Member, out _) is { } denied)
        {
            return denied;
        }

        var since = clock.NowMs - (Math.Clamp(days ?? 7, 1, 90) * 86_400_000L);
        return Results.Ok(db.Read(c => new
        {
            daily = EventRepository.DailyCounts(c, homeId, since).Select(d => new { d.Day, d.Type, d.Count }),
            commands = EventRepository.CommandReliability(c, homeId, since).Select(r => new { r.Device, r.Total, r.Acked, r.Failed, r.AvgAckMs }),
        }));
    }

    private static IResult Audit(HttpContext http, long homeId, Database db)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Owner, out _) is { } denied)
        {
            return denied;
        }

        return Results.Ok(db.Read(c => new
        {
            chainIntact = AuditRepository.FirstBrokenLink(c) is null,
            entries = AuditRepository.ForHome(c, homeId, 100).Select(a => new { a.Id, at = a.AtMs, a.UserId, a.Action, a.Detail }),
        }));
    }

    /// <summary>Live home events as Server-Sent Events, with a keep-alive comment every 15 s.</summary>
    private static async Task Stream(HttpContext http, long homeId, Database db, EventHub hub)
    {
        if (Access.Check(db, homeId, http.UserId(), HomeRole.Guest, out _) is { } denied)
        {
            await denied.ExecuteAsync(http);
            return;
        }

        http.Response.ContentType = "text/event-stream";
        http.Response.Headers.CacheControl = "no-store";
        var (id, reader) = hub.Subscribe(homeId);
        try
        {
            await http.Response.WriteAsync(": connected\n\n", http.RequestAborted);
            await http.Response.Body.FlushAsync(http.RequestAborted);
            while (!http.RequestAborted.IsCancellationRequested)
            {
                using var keepAlive = CancellationTokenSource.CreateLinkedTokenSource(http.RequestAborted);
                keepAlive.CancelAfter(TimeSpan.FromSeconds(15));
                string line;
                try
                {
                    if (!await reader.WaitToReadAsync(keepAlive.Token))
                    {
                        return; // home deleted
                    }

                    line = reader.TryRead(out var json) ? $"data: {json}\n\n" : "";
                }
                catch (OperationCanceledException) when (!http.RequestAborted.IsCancellationRequested)
                {
                    line = ": keep-alive\n\n";
                }

                if (line.Length > 0)
                {
                    await http.Response.WriteAsync(line, http.RequestAborted);
                    await http.Response.Body.FlushAsync(http.RequestAborted);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Client went away.
        }
        finally
        {
            hub.Unsubscribe(homeId, id);
        }
    }

    internal static JsonSerializerOptions Json => JsonDefaults.Options;
}
