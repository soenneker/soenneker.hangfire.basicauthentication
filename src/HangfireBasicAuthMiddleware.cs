using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Soenneker.Extensions.Configuration;
using Soenneker.Extensions.HttpContext;
using Soenneker.Extensions.String;

namespace Soenneker.Hangfire.BasicAuthentication;

/// <summary>
/// Allows for basic authentication via middleware
/// </summary>
public class HangfireBasicAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly bool _localAuthenticationBypassEnabled;
    private readonly string? _username;
    private readonly string? _password;
    private readonly string _url = "/hangfire";

    private readonly ILogger<HangfireBasicAuthMiddleware> _logger;

    public HangfireBasicAuthMiddleware(RequestDelegate next, IConfiguration config, ILogger<HangfireBasicAuthMiddleware> logger)
    {
        _next = next;
        _logger = logger;

        _username = config.GetValueStrict<string>("Hangfire:Username");
        _password = config.GetValueStrict<string>("Hangfire:Password");

        _localAuthenticationBypassEnabled = config.GetValueStrict<bool>("Hangfire:LocalAuthenticationBypassEnabled");

        var url = config.GetValue<string>("Hangfire:Url");

        if (url != null)
            _url = url;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!IsAuthenticationRequired(context))
        {
            await _next.Invoke(context);
            return;
        }

        if (!TryGetAuthorizationHeader(context, out string authHeader))
        {
            LogAndSetUnauthorized(context, "Authorization header missing or empty, possible first login attempt");
            return;
        }

        if (!IsBasicAuth(authHeader, out (string username, string password) credentials))
        {
            LogAndSetUnauthorized(context, "Authorization header malformed or does not start with 'Basic'");
            return;
        }

        if (AreCredentialsValid(credentials))
        {
            _logger.LogDebug("Authentication successful");
            await _next.Invoke(context);
            return;
        }

        LogAndSetUnauthorized(context, "Invalid credentials");
    }

    private bool IsAuthenticationRequired(HttpContext context)
    {
        if (_username == null || _password == null ||
            (_localAuthenticationBypassEnabled && context.IsLocalRequest()) ||
            !context.Request.Path.StartsWithSegments(_url))
        {
            return false;
        }

        return true;
    }

    private static bool TryGetAuthorizationHeader(HttpContext context, out string authHeader)
    {
        if (context.Request.Headers.TryGetValue(HeaderNames.Authorization, out StringValues headerValues))
        {
            authHeader = headerValues.ToString();

            if (authHeader.IsNullOrEmpty())
                return false;

            return true;
        }

        authHeader = "";
        return false;
    }

    private static bool IsBasicAuth(string authHeader, out (string username, string password) credentials)
    {
        if (authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            string encodedCredentials = authHeader["Basic ".Length..].Trim();
            string decodedCredentials = encodedCredentials.ToStringFromEncoded64();
            string[] parts = decodedCredentials.Split(':', 2);

            if (parts.Length == 2)
            {
                credentials = (parts[0], parts[1]);
                return true;
            }
        }

        credentials = ("", "");
        return false;
    }

    private bool AreCredentialsValid((string username, string password) credentials)
    {
        return credentials.username.Equals(_username, StringComparison.OrdinalIgnoreCase) &&
               credentials.password == _password;
    }

    private void LogAndSetUnauthorized(HttpContext context, string message)
    {
        _logger.LogWarning("{message}", message);
        context.SetUnauthorized();
    }
}