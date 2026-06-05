using Hangfire.Dashboard;

namespace Soenneker.Hangfire.BasicAuthentication;

/// <summary>
/// Needed to enable non-local traffic to flow into the hangfire auth middleware
/// </summary>
public sealed class HangfireAuthorizationFilter : IDashboardAuthorizationFilter
{
    /// <summary>
    /// Executes the authorize operation.
    /// </summary>
    /// <param name="dashboardContext">The dashboard context.</param>
    /// <returns>A value indicating whether the operation succeeded.</returns>
    public bool Authorize(DashboardContext dashboardContext)
    {
        return true;
    }
}