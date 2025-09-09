using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using Soenneker.Extensions.Configuration;
using Soenneker.Extensions.HttpContext;
using Soenneker.Extensions.String;
using Soenneker.Validators.BasicAuth.Abstract;

namespace Soenneker.Hangfire.BasicAuthentication;

/// <summary>
/// Basic Auth gate for /hangfire (or configured path), delegating parsing + verification to IBasicAuthValidator.
/// Keeps password only as a PHC record (no plaintext in config).
/// </summary>
public sealed class HangfireBasicAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<HangfireBasicAuthMiddleware> _logger;
    private readonly IBasicAuthValidator _basicAuthValidator;

    private readonly bool _localAuthenticationBypassEnabled;
    private readonly string? _username; // plain username
    private readonly string? _passwordPhc; // PBKDF2 PHC record
    private readonly PathString _url = "/hangfire";

    public HangfireBasicAuthMiddleware(RequestDelegate next, IConfiguration config, ILogger<HangfireBasicAuthMiddleware> logger,
        IBasicAuthValidator basicAuthValidator)
    {
        _next = next;
        _logger = logger;
        _basicAuthValidator = basicAuthValidator;

        _username = config.GetValueStrict<string>("Hangfire:Username");
        _passwordPhc = config.GetValueStrict<string>("Hangfire:PasswordPhc");
        _localAuthenticationBypassEnabled = config.GetValueStrict<bool>("Hangfire:LocalAuthenticationBypassEnabled");

        var url = config.GetValue<string>("Hangfire:Url");

        if (url.HasContent())
            _url = new PathString(url);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!IsAuthenticationRequired(context))
        {
            await _next(context);
            return;
        }

        // Fast existence check avoids logging on every anonymous hit
        if (!context.Request.Headers.ContainsKey(HeaderNames.Authorization))
        {
            LogAndSetUnauthorized(context, "Authorization header missing or empty, possible first login attempt");
            return;
        }

        bool ok = _basicAuthValidator.ValidateSafe(context, configuredUsername: _username, configuredPasswordPhc: _passwordPhc);

        if (!ok)
        {
            LogAndSetUnauthorized(context, "Invalid Basic credentials");
            return;
        }

        _logger.LogDebug("Authentication successful");
        await _next(context);
    }

    private bool IsAuthenticationRequired(HttpContext context)
    {
        if (_username is null || _passwordPhc is null)
            return false;

        if (_localAuthenticationBypassEnabled && context.IsLocalRequest())
            return false;

        if (!context.Request.Path.StartsWithSegments(_url))
            return false;

        return true;
    }

    private void LogAndSetUnauthorized(HttpContext context, string message)
    {
        _logger.LogWarning("{message}", message);
        context.Response.Headers.WWWAuthenticate = "Basic"; // prompt
        context.SetUnauthorized();
    }
}