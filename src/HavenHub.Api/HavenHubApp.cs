using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using HavenHub.Api.Infrastructure;
using HavenHub.Api.Services;
using HavenHub.Core;
using HavenHub.Core.Security;
using HavenHub.Data;
using Microsoft.AspNetCore.Authentication;

namespace HavenHub.Api;

/// <summary>Builds the web application. Tests call this with their own options, clock and port.</summary>
public static class HavenHubApp
{
    public static WebApplication Create(string[] args, Action<HavenHubOptions>? configure = null, IClock? clock = null, string? urls = null)
    {
        var builder = WebApplication.CreateBuilder(args);
        if (urls is not null)
        {
            builder.WebHost.UseUrls(urls);
        }

        builder.WebHost.ConfigureKestrel(k =>
        {
            k.AddServerHeader = false;
            k.Limits.MaxRequestBodySize = 64 * 1024;
        });

        var options = builder.Configuration.GetSection("HavenHub").Get<HavenHubOptions>() ?? new HavenHubOptions();
        configure?.Invoke(options);
        var isDev = builder.Environment.IsDevelopment();
        var appClock = clock ?? new HavenHub.Core.SystemClock();

        var services = builder.Services;
        services.AddSingleton(options);
        services.AddSingleton(appClock);
        services.AddSingleton(_ => new Database(options.DatabasePath));
        services.AddSingleton(new SecretBox(HavenHubOptions.ResolveKey(options.MasterKey, nameof(options.MasterKey), isDev, 32)));
        services.AddSingleton(new TokenService(
            HavenHubOptions.ResolveKey(options.TokenKey, nameof(options.TokenKey), isDev, 32), appClock, TimeSpan.FromMinutes(options.TokenLifetimeMinutes)));
        services.AddSingleton<EventHub>();
        services.AddSingleton<SecurityService>();
        services.AddSingleton<DeviceService>();
        services.AddSingleton<DeviceGateway>();
        services.AddSingleton<CommandService>();
        services.AddSingleton<Housekeeping>();
        services.AddHostedService(sp => sp.GetRequiredService<Housekeeping>());

        services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
        services.AddAuthentication(TokenAuthHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, TokenAuthHandler>(TokenAuthHandler.SchemeName, null);
        services.AddAuthorization();
        services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.AddPolicy("auth", http => RateLimitPartition.GetFixedWindowLimiter(
                http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions { PermitLimit = options.AuthRequestsPerMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
            // Separate buckets: installing devices must not use up the attempts a user needs to disarm.
            o.AddPolicy("pairing", http => RateLimitPartition.GetFixedWindowLimiter(
                http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions { PermitLimit = options.PairRequestsPerMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
            o.AddPolicy("pin", http => RateLimitPartition.GetFixedWindowLimiter(
                http.Request.Headers.Authorization.ToString(),
                _ => new FixedWindowRateLimiterOptions { PermitLimit = options.PinAttemptsPerMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
            o.AddPolicy("commands", http => RateLimitPartition.GetTokenBucketLimiter(
                http.Request.Headers.Authorization.ToString(),
                _ => new TokenBucketRateLimiterOptions
                {
                    TokenLimit = options.CommandsPerMinute,
                    TokensPerPeriod = options.CommandsPerMinute,
                    ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                }));
        });

        var app = builder.Build();
        app.Services.GetRequiredService<Database>().Write(DeviceRepository.MarkAllOffline);
        if (!isDev)
        {
            app.UseHsts();
        }

        app.UseMiddleware<SecurityHeadersMiddleware>();
        app.UseDefaultFiles();
        app.UseStaticFiles();
        app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(30) });
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseRateLimiter();
        Endpoints.Map(app);
        return app;
    }
}
