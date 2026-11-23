using System.Net;
using System.Text.Json.Nodes;
using HavenHub.Api;
using HavenHub.Api.Services;
using HavenHub.Core;
using HavenHub.Core.Devices;
using HavenHub.Data;
using HavenHub.DeviceSim;
using HavenHub.Tests.Framework;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace HavenHub.Tests.Api;

/// <summary>
/// Runs the real service in-process on a random local port with a temporary database and a
/// <see cref="ManualClock"/>, so tests control time (alarm delays, timeouts, token expiry) exactly.
/// Background housekeeping is slowed right down; tests call <see cref="Housekeep"/> when they need it.
/// </summary>
public sealed class TestServer : IAsyncDisposable
{
    private static int _serial;
    private readonly List<IAsyncDisposable> _owned = [];

    private TestServer(WebApplication app, ManualClock clock, string dir)
    {
        App = app;
        Clock = clock;
        Dir = dir;
        BaseUri = new Uri(app.Urls.First());
    }

    public WebApplication App { get; }

    public ManualClock Clock { get; }

    public string Dir { get; }

    public Uri BaseUri { get; }

    public Database Db => App.Services.GetRequiredService<Database>();

    public long Now() => ((IClock)Clock).NowMs;

    public static async Task<TestServer> StartAsync(Action<HavenHubOptions>? tweak = null)
    {
        var dir = Directory.CreateTempSubdirectory("havenhub-api-").FullName;
        var clock = new ManualClock(DateTimeOffset.UtcNow);
        var app = HavenHubApp.Create(
            ["--environment", "Development", "--Logging:LogLevel:Default", "Critical", "--contentRoot", Path.Combine(Runner.RepoRoot(), "src", "HavenHub.Api")],
            o =>
            {
                o.DatabasePath = Path.Combine(dir, "test.db");
                o.PasswordIterations = 1000; // keep tests fast; production default is 600,000
                o.CommandAckTimeoutSeconds = 2;
                o.HousekeepingIntervalMs = 3_600_000;
                o.AuthRequestsPerMinute = 10_000;
                o.PairRequestsPerMinute = 10_000;
                o.PinAttemptsPerMinute = 10_000;
                o.CommandsPerMinute = 10_000;
                tweak?.Invoke(o);
            },
            clock,
            "http://127.0.0.1:0");
        await app.StartAsync();
        return new TestServer(app, clock, dir);
    }

    public HavenHubClient Client()
    {
        var c = new HavenHubClient(BaseUri);
        _owned.Add(new AsyncDisposableAction(() => c.Dispose()));
        return c;
    }

    public Housekeeping.Summary Housekeep() => App.Services.GetRequiredService<Housekeeping>().RunOnce();

    /// <summary>Signs up a new user with their own home.</summary>
    public async Task<(HavenHubClient Api, long UserId, long HomeId)> OwnerWithHomeAsync(string pin = "2468")
    {
        var api = Client();
        var n = Interlocked.Increment(ref _serial);
        var userId = await api.SignUpAsync($"user{n}-{Guid.NewGuid():N}@example.com", "a-long-test-password");
        var homeId = await api.CreateHomeAsync($"Home {n}", pin);
        return (api, userId, homeId);
    }

    /// <summary>Pairs a simulated device, connects it and waits until the cloud has its first report.</summary>
    public async Task<SimDevice> DeviceAsync(HavenHubClient api, long homeId, DeviceKind kind, string? name = null, Zone? zone = null, bool connect = true)
    {
        var serial = $"{kind}-{Interlocked.Increment(ref _serial)}-{Guid.NewGuid():N}"[..30].ToUpperInvariant();
        var device = await api.PairAsync(homeId, kind, name ?? kind.ToString(), serial, Now, zone: zone);
        _owned.Add(device);
        if (connect)
        {
            await ConnectAsync(api, device);
        }

        return device;
    }

    public async Task ConnectAsync(HavenHubClient api, SimDevice device)
    {
        await device.ConnectAsync(api.DeviceSocketUri);
        await device.Welcomed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await WaitUntil(() => Db.Read(c => DeviceRepository.ById(c, device.DeviceId))!.StateVersion > 0, "first report stored");
    }

    public static async Task WaitUntil(Func<bool> condition, string what, int timeoutMs = 5000)
    {
        var until = Environment.TickCount64 + timeoutMs;
        while (!condition())
        {
            if (Environment.TickCount64 > until)
            {
                throw new AssertionException("timed out waiting for " + what);
            }

            await Task.Delay(10);
        }
    }

    public JsonObject DeviceState(long deviceId) => (JsonObject)JsonNode.Parse(Db.Read(c => DeviceRepository.ById(c, deviceId))!.StateJson)!;

    public async ValueTask DisposeAsync()
    {
        foreach (var o in _owned)
        {
            await o.DisposeAsync();
        }

        await App.StopAsync();
        await App.DisposeAsync();
        Directory.Delete(Dir, recursive: true);
    }

    public static void Status(HttpStatusCode expected, (HttpStatusCode Status, JsonNode? Body) response, string what) =>
        Assert.Equal(expected, response.Status, $"{what} {response.Body?.ToJsonString()}");

    private sealed class AsyncDisposableAction(Action action) : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            action();
            return ValueTask.CompletedTask;
        }
    }
}
