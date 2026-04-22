using AwesomeAssertions;
using Soenneker.Hashing.Pbkdf2;
using Soenneker.Tests.HostedUnit;

namespace Soenneker.Hangfire.BasicAuthentication.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public class HangfireAuthorizationFilterTests : HostedUnitTest
{
    public HangfireAuthorizationFilterTests(Host host) : base(host)
    {
    }

    [Test]
    public void Authorize_ShouldAlwaysReturnTrue()
    {
        var filter = new HangfireAuthorizationFilter();

        bool result = filter.Authorize(null!);

        result.Should().BeTrue();
    }

    [Test]
    public void GeneratePassword()
    {
        const string plainText = "mysecretpassword";

        string phc = Pbkdf2HashingUtil.Hash(plainText);

        string.IsNullOrWhiteSpace(phc).Should().BeFalse();
    }
}
