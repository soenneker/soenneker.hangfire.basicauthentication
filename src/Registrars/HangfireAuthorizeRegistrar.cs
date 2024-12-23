using Microsoft.AspNetCore.Builder;

namespace Soenneker.Hangfire.BasicAuthentication.Registrars;

public static class HangfireAuthorizeRegistrar
{
    /// <summary>
    /// Adds simple basic authorization to the Hangfire instance - Hangfire:Username, Hangfire:Password config values necessary.
    /// </summary>
    public static IApplicationBuilder UseHangfireAuthorized(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<HangfireBasicAuthMiddleware>();
    }
}