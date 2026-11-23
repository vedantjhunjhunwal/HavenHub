using System.Net.WebSockets;
using System.Text;
using System.Text.Json.Nodes;
using HavenHub.Core.Devices;
using HavenHub.Core.Protocol;

namespace HavenHub.DeviceSim;

/// <summary>
/// A simulated smart-home device speaking the HavenHub device protocol: it signs every message with
/// its secret, verifies every command from the cloud, applies commands to its state and acknowledges them.
/// </summary>
public sealed class SimDevice : IAsyncDisposable
{
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly Func<long> _now;
    private ClientWebSocket? _socket;
    private Task? _receiveLoop;
    private long _outSeq;
    private long _inSeq;

    public SimDevice(DeviceKind kind, string serial, byte[] secret, string firmware, Func<long> now, JsonObject? initialState = null)
    {
        Kind = kind;
        Serial = serial;
        Secret = secret;
        Firmware = firmware;
        _now = now;
        State = initialState ?? DefaultState(kind);
    }

    public DeviceKind Kind { get; }

    public string Serial { get; }

    public byte[] Secret { get; }

    public string Firmware { get; }

    public JsonObject State { get; }

    public long DeviceId { get; private set; }

    /// <summary>When true the device receives commands but never answers (to exercise ack timeouts).</summary>
    public bool Unresponsive { get; set; }

    /// <summary>Commands received from the cloud that passed signature checks.</summary>
    public int CommandsReceived { get; private set; }

    /// <summary>Messages from the cloud that failed verification (should stay 0).</summary>
    public int RejectedFromCloud { get; private set; }

    public string? CloseReason { get; private set; }

    public TaskCompletionSource Welcomed { get; private set; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public event Action<long, string>? CommandApplied;

    public static JsonObject DefaultState(DeviceKind kind) => kind switch
    {
        DeviceKind.Lock => new JsonObject { ["locked"] = true, ["jammed"] = false, ["battery"] = 90 },
        DeviceKind.Thermostat => new JsonObject { ["setpoint"] = 21.0, ["mode"] = "heat", ["temperature"] = 20.5 },
        DeviceKind.GarageDoor => new JsonObject { ["open"] = false, ["obstructed"] = false },
        DeviceKind.Light => new JsonObject { ["on"] = false, ["level"] = 100 },
        DeviceKind.ContactSensor => new JsonObject { ["open"] = false, ["battery"] = 80, ["tamper"] = false },
        DeviceKind.MotionSensor => new JsonObject { ["motion"] = false, ["battery"] = 80 },
        DeviceKind.Doorbell => new JsonObject { ["presses"] = 0, ["battery"] = 70 },
        _ => [],
    };

    public async Task ConnectAsync(Uri wsUri, CancellationToken ct = default)
    {
        Welcomed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        _socket = new ClientWebSocket();
        await _socket.ConnectAsync(wsUri, ct);
        await SendAsync(MessageTypes.Hello, new { firmware = Firmware }, ct);
        await SendAsync(MessageTypes.Report, new { state = State }, ct);
        _receiveLoop = Task.Run(() => ReceiveLoopAsync(_socket), CancellationToken.None);
    }

    public Task ReportAsync(JsonObject changes, CancellationToken ct = default)
    {
        foreach (var (k, v) in changes)
        {
            State[k] = v?.DeepClone();
        }

        return SendAsync(MessageTypes.Report, new { state = changes }, ct);
    }

    public Task HeartbeatAsync(CancellationToken ct = default) => SendAsync(MessageTypes.Heartbeat, new { }, ct);

    /// <summary>Sends a raw, already-built envelope (used by tests to replay or tamper with messages).</summary>
    public async Task SendRawAsync(string json, CancellationToken ct = default)
    {
        await _sendLock.WaitAsync(ct);
        try
        {
            await _socket!.SendAsync(Encoding.UTF8.GetBytes(json), WebSocketMessageType.Text, true, ct);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    public Envelope Build(string type, object body) => DeviceProtocol.Seal(Secret, type, Serial, Interlocked.Increment(ref _outSeq), _now(), body);

    public async Task SendAsync(string type, object body, CancellationToken ct = default) =>
        await SendRawAsync(DeviceProtocol.Serialize(Build(type, body)), ct);

    public async Task CloseAsync()
    {
        if (_socket is { State: WebSocketState.Open })
        {
            try
            {
                await _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None);
            }
            catch (WebSocketException)
            {
                // already closed
            }
        }

        if (_receiveLoop is not null)
        {
            await _receiveLoop;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await CloseAsync();
        _socket?.Dispose();
        _sendLock.Dispose();
    }

    private async Task ReceiveLoopAsync(ClientWebSocket socket)
    {
        var buffer = new byte[DeviceProtocol.MaxMessageBytes];
        try
        {
            while (socket.State == WebSocketState.Open)
            {
                var count = 0;
                ValueWebSocketReceiveResult result;
                do
                {
                    result = await socket.ReceiveAsync(buffer.AsMemory(count), CancellationToken.None);
                    count += result.Count;
                }
                while (!result.EndOfMessage && count < buffer.Length);

                if (result.MessageType == WebSocketMessageType.Close)
                {
                    CloseReason = socket.CloseStatusDescription;
                    return;
                }

                await HandleAsync(Encoding.UTF8.GetString(buffer, 0, count));
            }
        }
        catch (WebSocketException)
        {
            CloseReason ??= "connection_lost";
        }
        finally
        {
            Welcomed.TrySetException(new InvalidOperationException("closed before welcome: " + (socket.CloseStatusDescription ?? CloseReason)));
        }
    }

    private async Task HandleAsync(string json)
    {
        var msg = DeviceProtocol.Parse(json);
        if (msg is null || DeviceProtocol.Verify(msg, Secret, Serial, _inSeq, _now()) != EnvelopeCheck.Ok)
        {
            RejectedFromCloud++;
            return;
        }

        _inSeq = msg.Seq;
        var body = JsonNode.Parse(msg.Body)!.AsObject();
        switch (msg.Type)
        {
            case MessageTypes.Welcome:
                DeviceId = body["deviceId"]!.GetValue<long>();
                Welcomed.TrySetResult();
                break;
            case MessageTypes.Command:
                CommandsReceived++;
                if (Unresponsive)
                {
                    return;
                }

                var id = body["id"]!.GetValue<long>();
                var action = body["action"]!.GetValue<string>();
                var (ok, error, changes) = Apply(action, body["args"] as JsonObject ?? []);
                foreach (var (k, v) in changes)
                {
                    State[k] = v?.DeepClone();
                }

                await SendAsync(MessageTypes.Ack, new { id, ok, error, state = changes });
                CommandApplied?.Invoke(id, action);
                break;
        }
    }

    private (bool Ok, string? Error, JsonObject Changes) Apply(string action, JsonObject args)
    {
        bool Flag(string k) => State[k]?.GetValue<bool>() == true;
        return (Kind, action) switch
        {
            (DeviceKind.Lock, "lock") when Flag("jammed") => (false, "bolt_jammed", []),
            (DeviceKind.Lock, "lock") => (true, null, new JsonObject { ["locked"] = true }),
            (DeviceKind.Lock, "unlock") => (true, null, new JsonObject { ["locked"] = false }),
            (DeviceKind.Thermostat, "set_setpoint") => (true, null, new JsonObject { ["setpoint"] = args["celsius"]?.DeepClone() }),
            (DeviceKind.Thermostat, "set_mode") => (true, null, new JsonObject { ["mode"] = args["mode"]?.DeepClone() }),
            (DeviceKind.GarageDoor, "close") when Flag("obstructed") => (false, "obstructed", []),
            (DeviceKind.GarageDoor, "open") => (true, null, new JsonObject { ["open"] = true }),
            (DeviceKind.GarageDoor, "close") => (true, null, new JsonObject { ["open"] = false }),
            (DeviceKind.Light, "on") => (true, null, new JsonObject { ["on"] = true }),
            (DeviceKind.Light, "off") => (true, null, new JsonObject { ["on"] = false }),
            (DeviceKind.Light, "dim") => (true, null, new JsonObject { ["on"] = true, ["level"] = args["level"]?.DeepClone() }),
            _ => (false, "unsupported", []),
        };
    }
}
