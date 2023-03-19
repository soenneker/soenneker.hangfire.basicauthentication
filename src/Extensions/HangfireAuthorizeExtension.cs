namespace Soenneker.Hangfire.BasicAuthentication.Extensions;
using Microsoft.AspNetCore.Builder;

public static class HangfireAuthorizeExtensions
{
    /// <summary>
    /// Adds simple basic authorization to the Hangfire instance - Hangfire:Username, Hangfire:Password config values necessary.
    /// </summary>
    public static IApplicationBuilder UseHangfireAuthorized(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<HangfireBasicAuthMiddleware>();
    }
}