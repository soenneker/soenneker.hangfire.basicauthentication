using Hangfire.Dashboard;

namespace Soenneker.Hangfire.BasicAuthentication;

/// <summary>
/// Needed to enable non-local traffic to flow into the hangfire auth middleware
/// </summary>
public sealed class HangfireAuthorizationFilter : IDashboardAuthorizationFilter
{
    public bool Authorize(DashboardContext dashboardContext)
    {
        return true;
    }
}