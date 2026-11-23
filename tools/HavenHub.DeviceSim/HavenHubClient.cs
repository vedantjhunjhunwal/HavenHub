using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using HavenHub.Core.Devices;

namespace HavenHub.DeviceSim;

/// <summary>Thin typed client for the HavenHub REST API, used by the demo, the load test and the tests.</summary>
public sealed class HavenHubClient : IDisposable
{
    public static readonly JsonSerializerOptions Json = CreateJson();

    /// <summary>Creates a client that owns its HttpClient and disposes it with itself.</summary>
    public HavenHubClient(Uri baseUri) => Http = new HttpClient { BaseAddress = baseUri, Timeout = TimeSpan.FromSeconds(30) };

    public HttpClient Http { get; }

    public Uri BaseUri => Http.BaseAddress!;

    public Uri DeviceSocketUri => new UriBuilder(BaseUri) { Scheme = BaseUri.Scheme == "https" ? "wss" : "ws", Path = "/device/ws" }.Uri;

    public static HavenHubClient Create(Uri baseUri) => new(baseUri);

    public void UseToken(string token) => Http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

    public async Task<(HttpStatusCode Status, JsonNode? Body)> SendAsync(HttpMethod method, string path, object? body = null, CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(method, new Uri(path, UriKind.Relative));
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, options: Json);
        }

        using var response = await Http.SendAsync(request, ct);
        var text = await response.Content.ReadAsStringAsync(ct);
        return (response.StatusCode, string.IsNullOrEmpty(text) ? null : JsonNode.Parse(text));
    }

    public Task<(HttpStatusCode Status, JsonNode? Body)> GetAsync(string path) => SendAsync(HttpMethod.Get, path);

    public Task<(HttpStatusCode Status, JsonNode? Body)> PostAsync(string path, object? body = null) => SendAsync(HttpMethod.Post, path, body ?? new { });

    public Task<(HttpStatusCode Status, JsonNode? Body)> DeleteAsync(string path, object? body = null) => SendAsync(HttpMethod.Delete, path, body);

    /// <summary>Registers (if needed) and logs in; the client then carries the token.</summary>
    public async Task<long> SignUpAsync(string email, string password)
    {
        await PostAsync("/api/auth/register", new { email, password });
        var (status, body) = await PostAsync("/api/auth/login", new { email, password });
        Expect(status, HttpStatusCode.OK, body);
        UseToken(body!["token"]!.GetValue<string>());
        var (_, me) = await GetAsync("/api/me");
        return me!["id"]!.GetValue<long>();
    }

    public async Task<long> CreateHomeAsync(string name, string pin)
    {
        var (status, body) = await PostAsync("/api/homes", new { name, panelPin = pin });
        Expect(status, HttpStatusCode.Created, body);
        return body!["id"]!.GetValue<long>();
    }

    /// <summary>Owner creates a pairing code, then the device redeems it, as during real installation.</summary>
    public async Task<SimDevice> PairAsync(long homeId, DeviceKind kind, string name, string serial, Func<long> now, string firmware = "2.1.0", Zone? zone = null)
    {
        var (status, body) = await PostAsync($"/api/homes/{homeId}/pairing-codes", new { kind, name, zone });
        Expect(status, HttpStatusCode.OK, body);
        var code = body!["code"]!.GetValue<string>();

        using var anonymous = new HttpClient { BaseAddress = BaseUri };
        using var response = await anonymous.PostAsJsonAsync("/device/pair", new { code, serial, firmware }, Json);
        var paired = await response.Content.ReadFromJsonAsync<JsonObject>(Json);
        Expect(response.StatusCode, HttpStatusCode.OK, paired);
        return new SimDevice(kind, serial, Convert.FromBase64String(paired!["secret"]!.GetValue<string>()), firmware, now);
    }

    public Task<(HttpStatusCode Status, JsonNode? Body)> CommandAsync(long homeId, long deviceId, string action, object? args = null, string? key = null, bool wait = true) =>
        PostAsync($"/api/homes/{homeId}/devices/{deviceId}/commands{(wait ? "?wait=true" : "")}", new { action, args = args ?? new { }, idempotencyKey = key });

    public void Dispose() => Http.Dispose();

    public static void Expect(HttpStatusCode actual, HttpStatusCode expected, JsonNode? body)
    {
        if (actual != expected)
        {
            throw new HttpRequestException($"expected {(int)expected} but got {(int)actual}: {body?.ToJsonString()}");
        }
    }

    private static JsonSerializerOptions CreateJson()
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        o.Converters.Add(new JsonStringEnumConverter());
        return o;
    }
}
