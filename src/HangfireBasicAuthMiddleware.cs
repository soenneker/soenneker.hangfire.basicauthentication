using System;
using System.Text;
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
/// Allocation/perf-optimized Basic Auth gate for /hangfire (or configured path).
/// Avoids string concatenations, Split, and unnecessary intermediate strings.
/// </summary>
public sealed class HangfireBasicAuthMiddleware
{
    private static ReadOnlySpan<char> BasicPrefix => "Basic ";

    private readonly RequestDelegate _next;
    private readonly bool _localAuthenticationBypassEnabled;
    private readonly string? _username;
    private readonly string? _password;
    private readonly PathString _url = "/hangfire";

    private readonly ILogger<HangfireBasicAuthMiddleware> _logger;

    public HangfireBasicAuthMiddleware(RequestDelegate next, IConfiguration config, ILogger<HangfireBasicAuthMiddleware> logger)
    {
        _next = next;
        _logger = logger;

        _username = config.GetValueStrict<string>("Hangfire:Username");
        _password = config.GetValueStrict<string>("Hangfire:Password");
        _localAuthenticationBypassEnabled = config.GetValueStrict<bool>("Hangfire:LocalAuthenticationBypassEnabled");

        var url = config.GetValue<string>("Hangfire:Url");

        if (url.HasContent())
            _url = new PathString(url);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Quick exits, no header parsing if not needed
        if (!IsAuthenticationRequired(context))
        {
            await _next(context);
            return;
        }

        if (!TryGetAuthorizationHeader(context, out ReadOnlySpan<char> header))
        {
            LogAndSetUnauthorized(context, "Authorization header missing or empty, possible first login attempt");
            return;
        }

        if (!TryValidateBasic(header))
        {
            LogAndSetUnauthorized(context, "Invalid or malformed Basic credentials");
            return;
        }

        _logger.LogDebug("Authentication successful");
        await _next(context);
    }

    private bool IsAuthenticationRequired(HttpContext context)
    {
        // If username/password not configured, or bypass for local requests, or not matching path -> skip auth
        if (_username is null || _password is null)
            return false;

        if (_localAuthenticationBypassEnabled && context.IsLocalRequest())
            return false;

        if (!context.Request.Path.StartsWithSegments(_url))
            return false;

        return true;
    }

    private static bool TryGetAuthorizationHeader(HttpContext context, out ReadOnlySpan<char> value)
    {
        // Avoids StringValues.ToString() which may allocate (and join multiple values)
        if (context.Request.Headers.TryGetValue(HeaderNames.Authorization, out StringValues values) && values.Count > 0)
        {
            // The header is typically single-valued. Using the first value avoids joining.
            string s = values[0];

            if (s.HasContent())
            {
                value = s.AsSpan();
                return true;
            }
        }

        value = ReadOnlySpan<char>.Empty;
        return false;
    }

    private bool TryValidateBasic(ReadOnlySpan<char> header)
    {
        // Check prefix without allocating
        if (header.Length < BasicPrefix.Length || !header.StartsWith(BasicPrefix, StringComparison.OrdinalIgnoreCase))
            return false;

        ReadOnlySpan<char> b64 = header.Slice(BasicPrefix.Length).Trim();
        if (b64.IsEmpty)
            return false;

        // Base64 chars -> bytes max length is (len/4)*3. Use stackalloc to avoid heap alloc (headers are tiny).
        int maxDecoded = (b64.Length / 4) * 3 + 3; // +3 slop for padding
        Span<byte> bytes = maxDecoded <= 1024 ? stackalloc byte[maxDecoded] : new byte[maxDecoded];

        if (!Convert.TryFromBase64Chars(b64, bytes, out int bytesWritten) || bytesWritten == 0)
            return false;

        bytes = bytes.Slice(0, bytesWritten);

        // Decode UTF-8 into a char buffer ("username:password"). RFC 7617 allows non-ASCII; UTF-8 is de facto.
        Encoding enc = Encoding.UTF8;
        int charCount = enc.GetCharCount(bytes);
        Span<char> chars = charCount <= 1024 ? stackalloc char[charCount] : new char[charCount];
        enc.GetChars(bytes, chars);

        int sep = chars.IndexOf(':');
        if (sep <= 0) // no username or no colon
            return false;

        ReadOnlySpan<char> user = chars.Slice(0, sep);
        ReadOnlySpan<char> pass = chars.Slice(sep + 1);

        // Compare without allocating new strings
        return AreCredentialsValid(user, pass);
    }

    private bool AreCredentialsValid(ReadOnlySpan<char> user, ReadOnlySpan<char> pass)
    {
        // Username: case-insensitive, Password: case-sensitive
        // Avoids string allocations by comparing spans to existing strings
        if (_username is null || _password is null)
            return false;

        bool userOk = user.Equals(_username.AsSpan(), StringComparison.OrdinalIgnoreCase);

        if (!userOk)
            return false;

        // Optional: constant-time compare for password to reduce timing side channels
        return ConstantTimeEquals(pass, _password.AsSpan());
    }

    private static bool ConstantTimeEquals(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        // Early length check (still constant-ish)
        if (a.Length != b.Length)
            return false;

        // XOR over UInt16 char units
        var diff = 0;
        
        for (var i = 0; i < a.Length; i++)
        {
            diff |= a[i] ^ b[i];
        }
        
        return diff == 0;
    }

    private void LogAndSetUnauthorized(HttpContext context, string message)
    {
        _logger.LogWarning("{message}", message);

        // Encourage clients to prompt for credentials. Header value intentionally simple.
        context.Response.Headers.WWWAuthenticate = "Basic";
        context.SetUnauthorized();
    }
}
