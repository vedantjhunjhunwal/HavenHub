using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using HavenHub.Api.Infrastructure;
using HavenHub.Core;
using HavenHub.Core.Devices;
using HavenHub.Data;

namespace HavenHub.Api.Services;

public sealed record CommandRequest(string Action, JsonObject? Args, string? IdempotencyKey);

/// <summary>
/// Validates, records and delivers user commands to devices, and tracks each to a final status.
/// Every command is idempotent per user and key, so a phone app can safely retry after a network drop
/// without unlocking a door twice.
/// </summary>
public sealed class CommandService(Database db, IClock clock, HavenHubOptions options, DeviceGateway gateway, EventHub hub)
{
    private static readonly HashSet<string> Audited = ["unlock", "open"];
    private readonly ConcurrentDictionary<long, TaskCompletionSource<CommandRow>> _waiters = new();

    public async Task<IResult> SubmitAsync(long userId, long homeId, long deviceId, HomeRole role, CommandRequest request, bool wait, CancellationToken ct)
    {
        var key = string.IsNullOrWhiteSpace(request.IdempotencyKey) ? Guid.NewGuid().ToString("N") : request.IdempotencyKey.Trim();
        if (key.Length > 64)
        {
            return ApiError.BadRequest("idempotencyKey must be at most 64 characters");
        }

        var args = request.Args ?? [];
        var now = clock.NowMs;
        var (error, cmd) = db.Transaction<(IResult? Error, CommandRow? Cmd)>(c =>
        {
            var existing = CommandRepository.ByIdempotencyKey(c, userId, key);
            if (existing is not null)
            {
                return existing.DeviceId == deviceId && existing.Action == request.Action
                    ? (null, existing)
                    : (ApiError.Conflict("idempotency_key_reused"), null);
            }

            var device = DeviceRepository.ById(c, deviceId);
            if (device is null || device.HomeId != homeId)
            {
                return (ApiError.NotFound("device_not_found"), null);
            }

            var type = DeviceType.For(device.Kind);
            if (!type.Actions.Contains(request.Action))
            {
                return (ApiError.Unprocessable("unsupported_action"), null);
            }

            if (role < type.MinimumRole(request.Action))
            {
                return (ApiError.Forbidden($"{request.Action} requires {type.MinimumRole(request.Action)} role"), null);
            }

            var check = type.Check(request.Action, args, JsonNode.Parse(device.StateJson) as JsonObject ?? []);
            if (!check.Ok)
            {
                return (ApiError.Unprocessable(check.Error!), null);
            }

            var online = gateway.IsConnected(deviceId);
            var ttl = type.OfflineQueueTtl(request.Action);
            var offlineFail = !online && ttl == TimeSpan.Zero;
            var expires = now + (long)(online ? options.AckTimeout : ttl).TotalMilliseconds;
            var id = CommandRepository.Create(
                c, deviceId, homeId, userId, key, request.Action, args.ToJsonString(),
                offlineFail ? CommandStatus.Failed : CommandStatus.Pending, offlineFail ? "device_offline" : null, now, expires);
            if (Audited.Contains(request.Action))
            {
                AuditRepository.Append(c, userId, homeId, "command:" + request.Action, $"{device.Name} (command {id})", now);
            }

            return (null, CommandRepository.ById(c, id));
        });

        if (error is not null)
        {
            return error;
        }

        if (cmd!.Status == CommandStatus.Pending && !cmd.IsFinal)
        {
            var waiter = wait ? _waiters.GetOrAdd(cmd.Id, _ => new(TaskCreationOptions.RunContinuationsAsynchronously)) : null;
            if (await gateway.SendCommandAsync(cmd, ct))
            {
                db.Write(c => CommandRepository.MarkSent(c, cmd.Id, clock.NowMs));
            }

            if (waiter is not null)
            {
                var done = await Task.WhenAny(waiter.Task, Task.Delay(options.AckTimeout, ct));
                _waiters.TryRemove(cmd.Id, out _);
                if (done == waiter.Task)
                {
                    return Results.Ok(Describe(await waiter.Task));
                }
            }

            cmd = db.Read(c => CommandRepository.ById(c, cmd.Id))!;
        }

        return Results.Json(Describe(cmd), statusCode: cmd.IsFinal ? StatusCodes.Status200OK : StatusCodes.Status202Accepted);
    }

    /// <summary>Sends queued commands to a device that has just (re)connected.</summary>
    public async Task DeliverPendingAsync(long deviceId, CancellationToken ct)
    {
        foreach (var cmd in db.Read(c => CommandRepository.PendingFor(c, deviceId, clock.NowMs)))
        {
            if (await gateway.SendCommandAsync(cmd, ct))
            {
                db.Write(c => CommandRepository.MarkSent(c, cmd.Id, clock.NowMs));
            }
        }
    }

    public void OnAck(long deviceId, long commandId, bool ok, string? error)
    {
        var row = db.Write(c => CommandRepository.Complete(c, commandId, deviceId, ok, error, clock.NowMs) ? CommandRepository.ById(c, commandId) : null);
        if (row is not null)
        {
            Finish(row);
        }
    }

    /// <summary>Applies ack timeouts and offline-queue expiry.</summary>
    public int Sweep()
    {
        var swept = db.Transaction(c => CommandRepository.Sweep(c, clock.NowMs, (long)options.AckTimeout.TotalMilliseconds));
        foreach (var cmd in swept)
        {
            Finish(db.Read(c => CommandRepository.ById(c, cmd.Id))!);
        }

        return swept.Count;
    }

    public static object Describe(CommandRow c) => new
    {
        c.Id,
        c.DeviceId,
        c.Action,
        args = JsonNode.Parse(c.ArgsJson),
        c.Status,
        c.Error,
        c.CreatedMs,
        c.SentMs,
        c.CompletedMs,
        c.IdempotencyKey,
    };

    private void Finish(CommandRow row)
    {
        if (_waiters.TryRemove(row.Id, out var waiter))
        {
            waiter.TrySetResult(row);
        }

        hub.Publish(row.HomeId, "command", Describe(row));
    }
}
