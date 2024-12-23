using Soenneker.Tests.FixturedUnit;
using Xunit;

namespace Soenneker.Hangfire.BasicAuthentication.Tests;

[Collection("Collection")]
public class HangfireAuthorizationFilterTests : FixturedUnitTest
{
    public HangfireAuthorizationFilterTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
    }

    [Fact]
    public void Default()
    {
    }
}
