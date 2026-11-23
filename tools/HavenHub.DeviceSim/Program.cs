using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using HavenHub.Core.Devices;
using HavenHub.DeviceSim;

// HavenHub device simulator.
//   demo  : one home, seven devices, a scripted day (commands, arming, a break-in, disarm).
//   load  : many homes and connected devices sending telemetry while users send commands; prints latency.
// Usage: HavenHub.DeviceSim demo|load [--url http://localhost:5080] [--homes 50] [--seconds 30] [--workers 32]
//        demo also takes [--email E --password P] and [--hold SECONDS] to keep devices online afterwards.
var mode = args.FirstOrDefault() ?? "demo";
string Opt(string name, string fallback)
{
    var i = Array.IndexOf(args, "--" + name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : fallback;
}

var url = new Uri(Opt("url", "http://localhost:5080"));
long Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
var runId = Now().ToString(CultureInfo.InvariantCulture);

return mode switch
{
    "demo" => await Demo(),
    "load" => await Load(int.Parse(Opt("homes", "50"), CultureInfo.InvariantCulture), int.Parse(Opt("seconds", "30"), CultureInfo.InvariantCulture), int.Parse(Opt("workers", "32"), CultureInfo.InvariantCulture)),
    _ => Usage(),
};

static int Usage()
{
    Console.Error.WriteLine("usage: HavenHub.DeviceSim demo|load [--url URL] [--homes N] [--seconds S] [--workers W] [--email E --password P --hold S]");
    return 2;
}

async Task<int> Demo()
{
    using var api = HavenHubClient.Create(url);
    await api.SignUpAsync(Opt("email", $"owner-{runId}@example.com"), Opt("password", "correct-horse-battery-staple"));
    var home = await api.CreateHomeAsync("Demo Home", "2468");
    Console.WriteLine($"Home {home} created");

    var specs = new (DeviceKind Kind, string Name)[]
    {
        (DeviceKind.Lock, "Front door lock"), (DeviceKind.ContactSensor, "Front door"), (DeviceKind.MotionSensor, "Hallway motion"),
        (DeviceKind.GarageDoor, "Garage door"), (DeviceKind.Thermostat, "Thermostat"), (DeviceKind.Light, "Porch light"), (DeviceKind.Doorbell, "Video doorbell"),
    };
    var devices = new Dictionary<string, SimDevice>();
    foreach (var (kind, name) in specs)
    {
        var d = await api.PairAsync(home, kind, name, $"{kind}-{runId}".ToUpperInvariant()[..Math.Min(40, kind.ToString().Length + 14)], Now);
        await d.ConnectAsync(api.DeviceSocketUri);
        await d.Welcomed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        devices[name] = d;
        Console.WriteLine($"  paired + connected: {name} (device {d.DeviceId})");
    }

    async Task Command(string device, string action, object? args = null)
    {
        var sw = Stopwatch.StartNew();
        var (status, body) = await api.CommandAsync(home, devices[device].DeviceId, action, args);
        Console.WriteLine($"  {device}: {action} -> {(int)status} {body?["status"] ?? body?["error"]} in {sw.ElapsedMilliseconds} ms");
    }

    Console.WriteLine("Commands:");
    await Command("Front door lock", "unlock");
    await Command("Front door lock", "lock");
    await Command("Thermostat", "set_setpoint", new { celsius = 22.5 });
    await Command("Porch light", "dim", new { level = 40 });
    await devices["Garage door"].ReportAsync(new JsonObject { ["obstructed"] = true });
    await Task.Delay(200);
    await Command("Garage door", "close");

    Console.WriteLine("Security:");
    var (s1, b1) = await api.PostAsync($"/api/homes/{home}/security/arm", new { mode = "ArmedAway", bypass = false });
    Console.WriteLine($"  arm away -> {(int)s1} {b1?["alarm"]}");
    var exit = await api.GetAsync($"/api/homes/{home}/security");
    var deadline = exit.Body?["deadlineMs"]?.GetValue<long>() ?? Now();
    await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(0, deadline - Now()) + 600));
    Console.WriteLine($"  after exit delay -> {(await api.GetAsync($"/api/homes/{home}/security")).Body?["alarm"]}");
    await devices["Front door"].ReportAsync(new JsonObject { ["open"] = true });
    await Task.Delay(300);
    var entry = await api.GetAsync($"/api/homes/{home}/security");
    Console.WriteLine($"  front door opened -> {entry.Body?["alarm"]}");
    var entryDeadline = entry.Body?["deadlineMs"]?.GetValue<long>() ?? Now();
    await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(0, entryDeadline - Now()) + 600));
    Console.WriteLine($"  nobody disarmed -> {(await api.GetAsync($"/api/homes/{home}/security")).Body?["alarm"]}");
    var (s2, _) = await api.PostAsync($"/api/homes/{home}/security/disarm", new { pin = "0000" });
    Console.WriteLine($"  disarm with wrong PIN -> {(int)s2}");
    var (s3, b3) = await api.PostAsync($"/api/homes/{home}/security/disarm", new { pin = "2468" });
    Console.WriteLine($"  disarm with PIN -> {(int)s3} {b3?["mode"]}");

    var (_, events) = await api.GetAsync($"/api/homes/{home}/events?limit=8");
    Console.WriteLine("Latest events:");
    foreach (var e in events!["items"]!.AsArray())
    {
        Console.WriteLine($"  {e!["type"]} {e["detail"]}");
    }

    var (_, audit) = await api.GetAsync($"/api/homes/{home}/audit");
    Console.WriteLine($"Audit log entries: {audit!["entries"]!.AsArray().Count}, hash chain intact: {audit["chainIntact"]}");
    var hold = int.Parse(Opt("hold", "0"), CultureInfo.InvariantCulture);
    if (hold > 0)
    {
        Console.WriteLine($"Keeping devices connected for {hold} s (open the dashboard now)...");
        await Task.Delay(TimeSpan.FromSeconds(hold));
    }

    foreach (var d in devices.Values)
    {
        await d.DisposeAsync();
    }

    var ok = s3 == HttpStatusCode.OK && audit["chainIntact"]!.GetValue<bool>();
    Console.WriteLine(ok ? "DEMO OK" : "DEMO FAILED");
    return ok ? 0 : 1;
}

async Task<int> Load(int homes, int seconds, int workers)
{
    var kinds = new[] { DeviceKind.Lock, DeviceKind.ContactSensor, DeviceKind.MotionSensor, DeviceKind.GarageDoor, DeviceKind.Thermostat, DeviceKind.Light, DeviceKind.Doorbell };
    var setup = Stopwatch.StartNew();
    var fleet = new ConcurrentBag<(HavenHubClient Api, long Home, SimDevice[] Devices)>();
    await Parallel.ForEachAsync(Enumerable.Range(0, homes), new ParallelOptions { MaxDegreeOfParallelism = 8 }, async (i, ct) =>
    {
        var api = HavenHubClient.Create(url);
        await api.SignUpAsync($"load-{runId}-{i}@example.com", "load-test-password-123");
        var home = await api.CreateHomeAsync($"Load home {i}", "8642");
        var devices = new List<SimDevice>();
        foreach (var kind in kinds)
        {
            var d = await api.PairAsync(home, kind, kind.ToString(), $"L{runId}-{i}-{(int)kind}", Now);
            await d.ConnectAsync(api.DeviceSocketUri, ct);
            await d.Welcomed.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            devices.Add(d);
        }

        fleet.Add((api, home, devices.ToArray()));
    });
    var all = fleet.ToArray();
    Console.WriteLine($"Setup: {homes} homes, {homes * kinds.Length} devices connected over signed WebSockets in {setup.Elapsed.TotalSeconds:F1} s");

    using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
    var latencies = new ConcurrentBag<double>();
    var outcomes = new ConcurrentDictionary<string, int>();
    long telemetry = 0;

    var commandWorkers = Enumerable.Range(0, workers).Select(w => Task.Run(async () =>
    {
        var rng = new Random(w);
        while (!stop.IsCancellationRequested)
        {
            var (api, home, devices) = all[rng.Next(all.Length)];
            var (device, action, args) = rng.Next(4) switch
            {
                0 => (devices[0], rng.Next(2) == 0 ? "lock" : "unlock", (object?)null),
                1 => (devices[4], "set_setpoint", new { celsius = 18 + rng.Next(8) }),
                2 => (devices[5], "dim", new { level = 1 + rng.Next(100) }),
                _ => (devices[5], rng.Next(2) == 0 ? "on" : "off", (object?)null),
            };
            var sw = Stopwatch.StartNew();
            var (status, body) = await api.CommandAsync(home, device.DeviceId, action, args);
            sw.Stop();
            var outcome = status == HttpStatusCode.OK ? body?["status"]?.ToString() ?? "?" : ((int)status).ToString(CultureInfo.InvariantCulture);
            outcomes.AddOrUpdate(outcome, 1, (_, n) => n + 1);
            if (outcome == "Acked")
            {
                latencies.Add(sw.Elapsed.TotalMilliseconds);
            }
        }
    })).ToList();

    // Every sensor reports roughly once a second; every device sends a heartbeat every 5 s.
    var telemetryWorker = Task.Run(async () =>
    {
        var rng = new Random(99);
        var tick = 0;
        while (!stop.IsCancellationRequested)
        {
            foreach (var (_, _, devices) in all)
            {
                await devices[1].ReportAsync(new JsonObject { ["battery"] = 60 + rng.Next(30) });
                await devices[2].ReportAsync(new JsonObject { ["motion"] = rng.Next(4) == 0 });
                Interlocked.Add(ref telemetry, 2);
                if (tick % 5 == 0)
                {
                    foreach (var d in devices)
                    {
                        await d.HeartbeatAsync();
                    }

                    Interlocked.Add(ref telemetry, devices.Length);
                }
            }

            tick++;
            await Task.Delay(1000);
        }
    });

    await Task.WhenAll(commandWorkers.Append(telemetryWorker));
    var sorted = latencies.OrderBy(x => x).ToArray();
    double P(double q) => sorted.Length == 0 ? double.NaN : sorted[Math.Min(sorted.Length - 1, (int)Math.Ceiling(q * sorted.Length) - 1)];
    var total = outcomes.Values.Sum();
    var rejectedByDevices = all.Sum(f => f.Devices.Sum(d => d.RejectedFromCloud));
    Console.WriteLine($"Commands: {total} in {seconds} s = {total / (double)seconds:F0}/s with {workers} concurrent clients");
    Console.WriteLine("Outcomes: " + string.Join(", ", outcomes.OrderBy(o => o.Key).Select(o => $"{o.Key}={o.Value}")));
    Console.WriteLine($"Round trip (API -> device -> ack -> API), acked commands: p50 {P(0.50):F1} ms, p95 {P(0.95):F1} ms, p99 {P(0.99):F1} ms");
    Console.WriteLine($"Telemetry + heartbeat messages: {telemetry} ({telemetry / (double)seconds:F0}/s)");
    Console.WriteLine($"Cloud messages rejected by devices (bad signature/order): {rejectedByDevices}");
    foreach (var (api, _, devices) in all)
    {
        foreach (var d in devices)
        {
            await d.DisposeAsync();
        }

        api.Dispose();
    }

    return outcomes.Keys.All(k => k == "Acked") && rejectedByDevices == 0 ? 0 : 1;
}
