using AwesomeAssertions;
using Soenneker.Hashing.Pbkdf2;
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
    public void Authorize_ShouldAlwaysReturnTrue()
    {
        var filter = new HangfireAuthorizationFilter();

        bool result = filter.Authorize(null!);

        result.Should().BeTrue();
    }

    [Fact]
    public void GeneratePassword()
    {
        const string plainText = "mysecretpassword";

        string phc = Pbkdf2HashingUtil.Hash(plainText);

        string.IsNullOrWhiteSpace(phc).Should().BeFalse();
    }
}
