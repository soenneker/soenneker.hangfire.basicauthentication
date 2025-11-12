using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using AwesomeAssertions;
using Soenneker.Hashing.Pbkdf2;
using Soenneker.Hangfire.BasicAuthentication;
using Soenneker.Hangfire.BasicAuthentication.Registrars;
using Soenneker.Validators.BasicAuth.Abstract;
using Xunit;

namespace Soenneker.Hangfire.BasicAuthentication.Tests;

[Collection("Collection")]
public class HangfireBasicAuthMiddlewareTests
{
    private const string Username = "user";
    private const string ValidPassword = "correct-password";

    [Fact]
    public async Task InvokeAsync_AllowsWhenPathDoesNotMatch()
    {
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        string passwordPhc = Pbkdf2HashingUtil.Hash(ValidPassword);
        HangfireBasicAuthMiddleware middleware = CreateMiddleware(next, passwordPhc);
        var context = new DefaultHttpContext
        {
            Request =
            {
                Path = "/other"
            }
        };

        await middleware.InvokeAsync(context);

        nextCalled.Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact]
    public async Task InvokeAsync_DeniesWhenHeaderMissing()
    {
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        string passwordPhc = Pbkdf2HashingUtil.Hash(ValidPassword);
        HangfireBasicAuthMiddleware middleware = CreateMiddleware(next, passwordPhc);
        var context = new DefaultHttpContext
        {
            Request =
            {
                Path = "/hangfire"
            }
        };

        await middleware.InvokeAsync(context);

        nextCalled.Should().BeFalse();
        context.Response.Headers.WWWAuthenticate.ToString().Should().Be("Basic");
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task InvokeAsync_DeniesWhenValidatorFails()
    {
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        string passwordPhc = Pbkdf2HashingUtil.Hash(ValidPassword);
        HangfireBasicAuthMiddleware middleware = CreateMiddleware(next, passwordPhc);
        var context = new DefaultHttpContext
        {
            Request =
            {
                Path = "/hangfire",
                Headers =
                {
                    Authorization = BuildAuthorizationHeader(Username, "wrong-password")
                }
            }
        };

        await middleware.InvokeAsync(context);

        nextCalled.Should().BeFalse();
        context.Response.Headers.WWWAuthenticate.ToString().Should().Be("Basic");
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task InvokeAsync_AllowsWhenValidatorSucceeds()
    {
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        string passwordPhc = Pbkdf2HashingUtil.Hash(ValidPassword);
        HangfireBasicAuthMiddleware middleware = CreateMiddleware(next, passwordPhc);
        var context = new DefaultHttpContext
        {
            Request =
            {
                Path = "/hangfire",
                Headers =
                {
                    Authorization = BuildAuthorizationHeader(Username, ValidPassword)
                }
            }
        };

        await middleware.InvokeAsync(context);

        nextCalled.Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact]
    public void Constructor_ThrowsWhenUsernameMissing()
    {
        RequestDelegate next = _ => Task.CompletedTask;

        IConfiguration configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["Hangfire:PasswordPhc"] = Pbkdf2HashingUtil.Hash(ValidPassword),
            ["Hangfire:LocalAuthenticationBypassEnabled"] = "false",
            ["Hangfire:Url"] = "/hangfire"
        });

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHangfireBasicAuth();
        services.AddSingleton(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();

        ILoggerFactory loggerFactory = provider.GetRequiredService<ILoggerFactory>();
        ILogger<HangfireBasicAuthMiddleware> logger = loggerFactory.CreateLogger<HangfireBasicAuthMiddleware>();
        IBasicAuthValidator validator = provider.GetRequiredService<IBasicAuthValidator>();

        Action act = () => new HangfireBasicAuthMiddleware(next, configuration, logger, validator);

        act.Should().Throw<NullReferenceException>();
    }

    private static HangfireBasicAuthMiddleware CreateMiddleware(RequestDelegate next, string passwordPhc)
    {
        IConfiguration configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["Hangfire:Username"] = Username,
            ["Hangfire:PasswordPhc"] = passwordPhc,
            ["Hangfire:LocalAuthenticationBypassEnabled"] = "false",
            ["Hangfire:Url"] = "/hangfire"
        });

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHangfireBasicAuth();
        services.AddSingleton<IConfiguration>(configuration);

        ServiceProvider provider = services.BuildServiceProvider();

        var loggerFactory = provider.GetRequiredService<ILoggerFactory>();
        ILogger<HangfireBasicAuthMiddleware> logger = loggerFactory.CreateLogger<HangfireBasicAuthMiddleware>();
        var validator = provider.GetRequiredService<IBasicAuthValidator>();

        return new HangfireBasicAuthMiddleware(next, configuration, logger, validator);
    }

    private static IConfiguration BuildConfiguration(IEnumerable<KeyValuePair<string, string?>> values)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
    }

    private static string BuildAuthorizationHeader(string username, string password)
    {
        var combined = $"{username}:{password}";
        string encoded = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(combined));
        return $"Basic {encoded}";
    }
}

