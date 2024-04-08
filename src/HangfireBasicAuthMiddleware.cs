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
        if (_username == null || _password == null)
        {
            context.SetUnauthorized();
            return;
        }

        if (_localAuthenticationBypassEnabled)
        {
            if (context.IsLocalRequest())
            {
                _logger.LogInformation("Local network request, skipping authentication");
                await _next.Invoke(context);
                return;
            }
        }

        if (!context.Request.Path.StartsWithSegments(_url))
        {
            await _next.Invoke(context);
            return;
        }

        if (!context.Request.Headers.TryGetValue(HeaderNames.Authorization, out StringValues stringValuesAuth))
        {
            _logger.LogDebug("Authorization header was null or empty... could be first login attempt to Hangfire");
            context.SetUnauthorized();
            return;
        }

        var authHeader = stringValuesAuth.ToString();

        if (authHeader.IsNullOrEmpty())
        {
            _logger.LogDebug("Authorization header was null or empty... could be first login attempt to Hangfire");
            context.SetUnauthorized();
            return;
        }

        if (authHeader.StartsWith("Basic "))
        {
            string? encodedUsernamePassword = authHeader.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries)[1]?.Trim();

            if (encodedUsernamePassword == null)
            {
                _logger.LogWarning("Hangfire basic auth early exit, bad encoding");
                context.SetUnauthorized();
                return;
            }

            string decodedUsernamePassword = encodedUsernamePassword.ToStringFromEncoded64();

            string[] credentialArray = decodedUsernamePassword.Split(':', 2);

            if (credentialArray.Length != 2)
            {
                _logger.LogWarning("Credentials are malformed (username and password must be split by ':')");
                context.SetUnauthorized();
                return;
            }

            string username = credentialArray[0];
            string password = credentialArray[1];

            if (username.Equals(_username, StringComparison.InvariantCultureIgnoreCase) && password == _password)
            {
                _logger.LogDebug("Hangfire authentication successful");
                await _next.Invoke(context);
                return;
            }
        }

        _logger.LogWarning("Authorization header was malformed (must start with 'Basic ')");
        context.SetUnauthorized();
    }
}