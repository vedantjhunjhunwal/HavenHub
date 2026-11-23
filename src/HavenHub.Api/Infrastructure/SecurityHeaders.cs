namespace HavenHub.Api.Infrastructure;

/// <summary>
/// Adds defensive HTTP headers to every response (OWASP Secure Headers): a strict Content Security
/// Policy (the dashboard loads only its own script and stylesheet), no MIME sniffing, no framing,
/// no referrer leakage and no caching of API responses.
/// </summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            var h = context.Response.Headers;
            h["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
            h["X-Content-Type-Options"] = "nosniff";
            h["X-Frame-Options"] = "DENY";
            h["Referrer-Policy"] = "no-referrer";
            h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
            h["Cross-Origin-Opener-Policy"] = "same-origin";
            if (context.Request.Path.StartsWithSegments("/api", StringComparison.Ordinal))
            {
                h.CacheControl = "no-store";
            }

            return Task.CompletedTask;
        });
        return next(context);
    }
}
