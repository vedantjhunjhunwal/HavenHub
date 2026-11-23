using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using HavenHub.Core;
using HavenHub.Core.Protocol;
using HavenHub.Data;

namespace HavenHub.Api.Services;

/// <summary>
/// Cloud end of the device connection: one authenticated WebSocket per device. Each side signs every
/// message with the device secret, so a device only accepts commands from the real cloud and the
/// cloud only accepts reports from the real device. Stale, out-of-order and replayed messages are refused.
/// </summary>
public sealed class DeviceGateway(Database db, IClock clock, HavenHubOptions options, IServiceProvider services, EventHub hub, ILogger<DeviceGateway> log)
{
    private static readonly TimeSpan HelloTimeout = TimeSpan.FromSeconds(5);
    private readonly ConcurrentDictionary<long, Session> _sessions = new();

    public int ConnectedCount => _sessions.Count;

    public bool IsConnected(long deviceId) => _sessions.ContainsKey(deviceId);

    public async Task<bool> SendCommandAsync(CommandRow cmd, CancellationToken ct)
    {
        if (!_sessions.TryGetValue(cmd.DeviceId, out var session))
        {
            return false;
        }

        try
        {
            await session.SendAsync(MessageTypes.Command, new { id = cmd.Id, action = cmd.Action, args = JsonNode.Parse(cmd.ArgsJson) }, clock.NowMs, ct);
            return true;
        }
        catch (WebSocketException)
        {
            return false;
        }
    }

    /// <summary>Drops a device's connection, e.g. when it is removed or its home is deleted.</summary>
    public void Disconnect(long deviceId)
    {
        // The connection's own handler (HandleAsync) unregisters and disposes the session when the socket dies.
        if (_sessions.TryGetValue(deviceId, out var s))
        {
            s.Socket.Abort();
        }
    }

    public async Task HandleAsync(HttpContext http)
    {
        if (!http.WebSockets.IsWebSocketRequest)
        {
            http.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        using var socket = await http.WebSockets.AcceptWebSocketAsync();
        var ct = http.RequestAborted;
        using var helloCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        helloCts.CancelAfter(HelloTimeout);

        string? helloJson;
        try
        {
            helloJson = await ReceiveAsync(socket, helloCts.Token);
        }
        catch (OperationCanceledException)
        {
            await CloseAsync(socket, WebSocketCloseStatus.PolicyViolation, "hello_timeout");
            return;
        }

        var (session, reason) = Authenticate(socket, helloJson);
        if (session is null)
        {
            log.LogWarning("Device connection refused: {Reason}", reason);
            await CloseAsync(socket, WebSocketCloseStatus.PolicyViolation, reason!);
            return;
        }

        if (_sessions.TryGetValue(session.Device.Id, out var old))
        {
            old.Socket.Abort(); // a device has one live connection; the newest wins
        }

        _sessions[session.Device.Id] = session;
        var now = clock.NowMs;
        db.Transaction(c =>
        {
            DeviceRepository.SetOnline(c, session.Device.Id, true, session.Firmware, now);
            EventRepository.Add(c, session.Device.HomeId, session.Device.Id, "device_online", session.Device.Name, now);
        });
        hub.Publish(session.Device.HomeId, "device_online", new { deviceId = session.Device.Id });
        await session.SendAsync(MessageTypes.Welcome, new { deviceId = session.Device.Id }, now, ct);
        await services.GetRequiredService<CommandService>().DeliverPendingAsync(session.Device.Id, ct);

        try
        {
            await RunAsync(session, ct);
        }
        catch (Exception e) when (e is WebSocketException or OperationCanceledException)
        {
            // Connection dropped; fall through to mark the device offline.
        }
        finally
        {
            if (_sessions.TryRemove(new KeyValuePair<long, Session>(session.Device.Id, session)))
            {
                var at = clock.NowMs;
                var stillPaired = db.Transaction(c =>
                {
                    if (DeviceRepository.ById(c, session.Device.Id) is null)
                    {
                        return false; // removed or its home deleted: nothing to record
                    }

                    DeviceRepository.SetOnline(c, session.Device.Id, false, null, at);
                    EventRepository.Add(c, session.Device.HomeId, session.Device.Id, "device_offline", session.Device.Name, at);
                    return true;
                });
                if (stillPaired)
                {
                    hub.Publish(session.Device.HomeId, "device_offline", new { deviceId = session.Device.Id });
                }
            }

            session.Dispose();
        }
    }

    private (Session? Session, string? Reason) Authenticate(WebSocket socket, string? json)
    {
        var hello = json is null ? null : DeviceProtocol.Parse(json);
        if (hello is null || hello.Type != MessageTypes.Hello)
        {
            return (null, "expected_hello");
        }

        var device = db.Read(c => DeviceRepository.BySerial(c, hello.Serial));
        if (device is null)
        {
            return (null, "unknown_device");
        }

        var secret = services.GetRequiredService<DeviceService>().SecretFor(device);
        var check = DeviceProtocol.Verify(hello, secret, device.Serial, long.MinValue, clock.NowMs);
        if (check != EnvelopeCheck.Ok)
        {
            return (null, "hello_" + check.ToString().ToUpperInvariant());
        }

        if (!db.Write(c => DeviceRepository.TryUseNonce(c, device.Id, hello.Nonce, clock.NowMs)))
        {
            return (null, "hello_REPLAYED");
        }

        var firmware = JsonNode.Parse(hello.Body)?["firmware"]?.GetValue<string>() ?? "0";
        if (DeviceProtocol.CompareVersions(firmware, options.MinimumFirmware) < 0)
        {
            return (null, "firmware_update_required");
        }

        return (new Session(device, secret, socket, firmware) { InSeq = hello.Seq }, null);
    }

    private async Task RunAsync(Session session, CancellationToken ct)
    {
        var devices = services.GetRequiredService<DeviceService>();
        var commands = services.GetRequiredService<CommandService>();
        while (session.Socket.State == WebSocketState.Open)
        {
            var json = await ReceiveAsync(session.Socket, ct);
            if (json is null)
            {
                return;
            }

            var msg = DeviceProtocol.Parse(json);
            var check = msg is null ? EnvelopeCheck.Malformed : DeviceProtocol.Verify(msg, session.Secret, session.Device.Serial, session.InSeq, clock.NowMs);
            if (check != EnvelopeCheck.Ok || !db.Write(c => DeviceRepository.TryUseNonce(c, session.Device.Id, msg!.Nonce, clock.NowMs)))
            {
                // Drop the message, not the connection: a single bad frame should not take a door lock offline.
                log.LogWarning("Rejected message from device {DeviceId}: {Check}", session.Device.Id, check == EnvelopeCheck.Ok ? "Replayed" : check);
                continue;
            }

            session.InSeq = msg!.Seq;
            var body = JsonNode.Parse(msg.Body) as JsonObject ?? [];
            switch (msg.Type)
            {
                case MessageTypes.Report when body["state"] is JsonObject state:
                    devices.ApplyReport(session.Device.Id, state);
                    break;
                case MessageTypes.Heartbeat:
                    db.Write(c => DeviceRepository.Touch(c, session.Device.Id, clock.NowMs));
                    break;
                case MessageTypes.Ack when body["id"] is JsonValue idNode && idNode.TryGetValue(out long commandId):
                    if (body["state"] is JsonObject newState)
                    {
                        devices.ApplyReport(session.Device.Id, newState);
                    }

                    commands.OnAck(session.Device.Id, commandId, body["ok"]?.GetValue<bool>() == true, body["error"]?.GetValue<string>());
                    break;
                default:
                    log.LogWarning("Unknown message type {Type} from device {DeviceId}", msg.Type, session.Device.Id);
                    break;
            }
        }
    }

    private static async Task<string?> ReceiveAsync(WebSocket socket, CancellationToken ct)
    {
        var buffer = new byte[DeviceProtocol.MaxMessageBytes];
        var count = 0;
        while (true)
        {
            if (count == buffer.Length)
            {
                await CloseAsync(socket, WebSocketCloseStatus.MessageTooBig, "message_too_big");
                return null;
            }

            var result = await socket.ReceiveAsync(buffer.AsMemory(count), ct);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                await CloseAsync(socket, WebSocketCloseStatus.NormalClosure, "bye");
                return null;
            }

            count += result.Count;
            if (result.EndOfMessage)
            {
                return Encoding.UTF8.GetString(buffer, 0, count);
            }
        }
    }

    private static async Task CloseAsync(WebSocket socket, WebSocketCloseStatus status, string reason)
    {
        if (socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
        {
            try
            {
                await socket.CloseOutputAsync(status, reason, CancellationToken.None);
            }
            catch (WebSocketException)
            {
                // Peer already gone.
            }
        }
    }

    private sealed class Session(Device device, byte[] secret, WebSocket socket, string firmware) : IDisposable
    {
        private readonly SemaphoreSlim _sendLock = new(1, 1);
        private long _outSeq;

        public Device Device { get; } = device;

        public byte[] Secret { get; } = secret;

        public WebSocket Socket { get; } = socket;

        public string Firmware { get; } = firmware;

        public long InSeq { get; set; }

        public void Dispose() => _sendLock.Dispose();

        public async Task SendAsync(string type, object body, long nowMs, CancellationToken ct)
        {
            await _sendLock.WaitAsync(ct);
            try
            {
                var envelope = DeviceProtocol.Seal(Secret, type, Device.Serial, ++_outSeq, nowMs, body);
                var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope);
                await Socket.SendAsync(bytes, WebSocketMessageType.Text, true, ct);
            }
            finally
            {
                _sendLock.Release();
            }
        }
    }
}
