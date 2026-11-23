using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using HavenHub.Core;

namespace HavenHub.Api.Services;

/// <summary>
/// In-process fan-out of live home events to dashboard streams (Server-Sent Events). Each subscriber
/// has a bounded queue; a slow client loses its oldest events instead of slowing the service down.
/// </summary>
public sealed class EventHub(IClock clock)
{
    private readonly ConcurrentDictionary<long, ConcurrentDictionary<Guid, Channel<string>>> _homes = new();

    public int SubscriberCount(long homeId) => _homes.TryGetValue(homeId, out var subs) ? subs.Count : 0;

    public (Guid Id, ChannelReader<string> Reader) Subscribe(long homeId)
    {
        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(256) { FullMode = BoundedChannelFullMode.DropOldest });
        var id = Guid.NewGuid();
        _homes.GetOrAdd(homeId, _ => new())[id] = channel;
        return (id, channel.Reader);
    }

    public void Unsubscribe(long homeId, Guid id)
    {
        if (_homes.TryGetValue(homeId, out var subs) && subs.TryRemove(id, out var channel))
        {
            channel.Writer.TryComplete();
        }
    }

    /// <summary>Ends every stream for a home (used when the home is deleted).</summary>
    public void Close(long homeId)
    {
        if (_homes.TryRemove(homeId, out var subs))
        {
            foreach (var channel in subs.Values)
            {
                channel.Writer.TryComplete();
            }
        }
    }

    public void Publish(long homeId, string type, object data)
    {
        if (!_homes.TryGetValue(homeId, out var subs) || subs.IsEmpty)
        {
            return;
        }

        var json = JsonSerializer.Serialize(new { type, at = clock.NowMs, data }, JsonDefaults.Options);
        foreach (var channel in subs.Values)
        {
            channel.Writer.TryWrite(json);
        }
    }
}

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        o.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
        return o;
    }
}
