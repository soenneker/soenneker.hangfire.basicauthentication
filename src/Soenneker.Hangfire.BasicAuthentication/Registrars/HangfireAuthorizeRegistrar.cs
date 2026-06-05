using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Soenneker.Validators.BasicAuth.Registrars;

namespace Soenneker.Hangfire.BasicAuthentication.Registrars;

/// <summary>
/// Represents the hangfire authorize registrar.
/// </summary>
public static class HangfireAuthorizeRegistrar
{
    /// <summary>
    /// Adds simple basic authorization to the Hangfire instance - Hangfire:Username, Hangfire:Password config values necessary.
    /// </summary>
    public static IApplicationBuilder UseHangfireAuthorized(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<HangfireBasicAuthMiddleware>();
    }

    /// <summary>
    /// Adds hangfire basic auth.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The result of the operation.</returns>
    public static IServiceCollection AddHangfireBasicAuth(this IServiceCollection services)
    {
        services.AddBasicAuthValidatorAsSingleton();
        return services;
    }
}