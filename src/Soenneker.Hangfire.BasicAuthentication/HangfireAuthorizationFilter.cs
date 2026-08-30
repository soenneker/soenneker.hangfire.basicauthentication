using Hangfire.Dashboard;

namespace Soenneker.Hangfire.BasicAuthentication;

/// <summary>
/// Allows dashboard requests through Hangfire's built-in authorization stage so the surrounding basic-authentication middleware can authorize them.
/// </summary>
public sealed class HangfireAuthorizationFilter : IDashboardAuthorizationFilter
{
    /// <summary>
    /// Determines whether the current request may access the Hangfire dashboard.
    /// </summary>
    /// <param name="dashboardContext">Context for the Hangfire dashboard request.</param>
    /// <returns>Always <see langword="true"/>; authorization is performed by <see cref="HangfireBasicAuthMiddleware"/>.</returns>
    public bool Authorize(DashboardContext dashboardContext)
    {
        return true;
    }
}
