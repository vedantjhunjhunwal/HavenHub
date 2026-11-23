using HavenHub.Core;
using HavenHub.Data;

namespace HavenHub.Api.Services;

/// <summary>
/// Periodic work: alarm-panel timers, command timeouts and expiry, devices that stopped sending
/// heartbeats, and pruning of old replay-protection nonces.
/// </summary>
public sealed class Housekeeping(
    Database db, IClock clock, HavenHubOptions options, SecurityService security, CommandService commands,
    DeviceGateway gateway, EventHub hub, ILogger<Housekeeping> log) : BackgroundService
{
    private long _lastPruneMs;

    public sealed record Summary(int PanelsTicked, int CommandsSwept, int DevicesMarkedOffline, int NoncesPruned);

    public Summary RunOnce()
    {
        var now = clock.NowMs;
        var ticked = security.Tick();
        var swept = commands.Sweep();

        var silent = db.Read(c => DeviceRepository.Silent(c, now - (options.HeartbeatTimeoutSeconds * 1000L)));
        foreach (var device in silent)
        {
            if (gateway.IsConnected(device.Id))
            {
                gateway.Disconnect(device.Id); // half-open socket: the connection handler records it going offline
                continue;
            }

            db.Transaction(c =>
            {
                DeviceRepository.SetOnline(c, device.Id, false, null, now);
                EventRepository.Add(c, device.HomeId, device.Id, "device_offline", device.Name + " (no heartbeat)", now);
            });
            hub.Publish(device.HomeId, "device_offline", new { deviceId = device.Id });
        }

        var pruned = 0;
        if (now - _lastPruneMs > 60_000)
        {
            // Nonces only need to outlive the accepted clock-skew window.
            pruned = db.Write(c => DeviceRepository.PruneNonces(c, now - (long)(2 * Core.Protocol.DeviceProtocol.ClockSkew.TotalMilliseconds)));
            _lastPruneMs = now;
        }

        return new Summary(ticked, swept, silent.Count, pruned);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(options.HousekeepingIntervalMs));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                RunOnce();
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // Keep the loop alive: one bad pass must not stop alarm timers for every home.
                log.LogError(e, "Housekeeping pass failed");
            }
        }
    }
}
