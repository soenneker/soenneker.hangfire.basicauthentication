using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Soenneker.Validators.BasicAuth.Registrars;

namespace Soenneker.Hangfire.BasicAuthentication.Registrars;

/// <summary>
/// Registers and adds Hangfire dashboard basic authentication.
/// </summary>
public static class HangfireAuthorizeRegistrar
{
    /// <summary>
    /// Adds the Hangfire basic-authentication middleware to the application pipeline.
    /// </summary>
    /// <param name="builder">Builder to configure.</param>
    /// <returns>The same builder instance, so additional classes or variants can be chained.</returns>
    public static IApplicationBuilder UseHangfireAuthorized(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<HangfireBasicAuthMiddleware>();
    }

    /// <summary>
    /// Registers the credential validator used by the Hangfire basic-authentication middleware.
    /// </summary>
    /// <param name="services">Service collection that receives the registration.</param>
    /// <returns>The same service collection, so additional registrations can be chained.</returns>
    public static IServiceCollection AddHangfireBasicAuth(this IServiceCollection services)
    {
        services.AddBasicAuthValidatorAsSingleton();
        return services;
    }
}
