using Hangfire.Dashboard;

namespace Soenneker.Hangfire.BasicAuthentication;

/// <summary>
/// Needed to enable non-local traffic to flow into the hangfire auth middleware
/// </summary>
public sealed class HangfireAuthorizationFilter : IDashboardAuthorizationFilter
{
    /// <summary>
    /// Determines whether the current request may access the Hangfire dashboard.
    /// </summary>
    /// <param name="dashboardContext">Context for the Hangfire dashboard request.</param>
    /// <returns>true if dashboard access is allowed; otherwise, false.</returns>
    public bool Authorize(DashboardContext dashboardContext)
    {
        return true;
    }
}
