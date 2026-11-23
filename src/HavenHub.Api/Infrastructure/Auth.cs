using System.Security.Claims;
using System.Text.Encodings.Web;
using HavenHub.Core.Devices;
using HavenHub.Core.Security;
using HavenHub.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace HavenHub.Api.Infrastructure;

/// <summary>
/// Validates "Authorization: Bearer &lt;token&gt;". A token is accepted only if its signature and expiry
/// check out and its version still matches the user's, so signing out everywhere revokes it at once.
/// </summary>
public sealed class TokenAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    TokenService tokens,
    Database db)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "HavenHubToken";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.Ordinal))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var claims = tokens.Validate(header["Bearer ".Length..].Trim());
        if (claims is null)
        {
            return Task.FromResult(AuthenticateResult.Fail("invalid or expired token"));
        }

        var user = db.Read(c => UserRepository.ById(c, claims.UserId));
        if (user is null || user.TokenVersion != claims.Version)
        {
            return Task.FromResult(AuthenticateResult.Fail("token revoked"));
        }

        var identity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, user.Id.ToString(System.Globalization.CultureInfo.InvariantCulture))], SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}

public static class HttpContextExtensions
{
    public static long UserId(this HttpContext http) =>
        long.Parse(http.User.FindFirstValue(ClaimTypes.NameIdentifier)!, System.Globalization.CultureInfo.InvariantCulture);
}

/// <summary>Per-home authorisation. Non-members get 404, not 403, so home ids cannot be probed.</summary>
public static class Access
{
    public static IResult? Check(Database db, long homeId, long userId, HomeRole minimum, out HomeRole role)
    {
        var found = db.Read(c => HomeRepository.RoleOf(c, homeId, userId));
        role = found ?? HomeRole.Guest;
        if (found is null)
        {
            return ApiError.NotFound("home_not_found");
        }

        return found < minimum ? ApiError.Forbidden($"requires {minimum} role") : null;
    }
}

/// <summary>Uniform JSON error bodies.</summary>
public static class ApiError
{
    public static IResult Error(int status, string error) => Results.Json(new { error }, statusCode: status);

    public static IResult BadRequest(string error) => Error(StatusCodes.Status400BadRequest, error);

    public static IResult Unauthorized(string error) => Error(StatusCodes.Status401Unauthorized, error);

    public static IResult Forbidden(string error) => Error(StatusCodes.Status403Forbidden, error);

    public static IResult NotFound(string error) => Error(StatusCodes.Status404NotFound, error);

    public static IResult Conflict(string error) => Error(StatusCodes.Status409Conflict, error);

    public static IResult Unprocessable(string error) => Error(StatusCodes.Status422UnprocessableEntity, error);

    public static IResult TooMany(string error) => Error(StatusCodes.Status429TooManyRequests, error);
}
