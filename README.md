[![](https://img.shields.io/nuget/v/Soenneker.Hangfire.BasicAuthentication.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Hangfire.BasicAuthentication/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hangfire.basicauthentication/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.hangfire.basicauthentication/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/Soenneker.Hangfire.BasicAuthentication.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Hangfire.BasicAuthentication/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hangfire.basicauthentication/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.hangfire.basicauthentication/actions/workflows/codeql.yml)

# Soenneker.Hangfire.BasicAuthentication

Represents the hangfire authorize registrar.

## Install

```bash
dotnet add package Soenneker.Hangfire.BasicAuthentication
```

## Quick start

```csharp
using Soenneker.Hangfire.BasicAuthentication.Registrars;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var result = services.AddHangfireBasicAuth();
```

Adds hangfire basic auth.

## What you get

- `HangfireAuthorizeRegistrar` — Represents the hangfire authorize registrar.
- `HangfireAuthorizationFilter` — Needed to enable non-local traffic to flow into the hangfire auth middleware.
- `HangfireBasicAuthMiddleware` — Basic Auth gate for /hangfire (or configured path), delegating parsing + verification to IBasicAuthValidator. Keeps password only as a PHC record (no plaintext in config).

## API at a glance

| API | What it does | Result / important behavior |
| --- | --- | --- |
| `HangfireAuthorizeRegistrar.UseHangfireAuthorized(builder)` | Adds simple basic authorization to the Hangfire instance - Hangfire:Username, Hangfire:Password config values necessary. | The same builder instance, so additional classes or variants can be chained. |
| `HangfireAuthorizationFilter.Authorize(dashboardContext)` | Determines whether the current request may access the Hangfire dashboard. | true if dashboard access is allowed; otherwise, false. |
| `HangfireBasicAuthMiddleware.InvokeAsync(context)` | Invokes async. | A task that completes when the invoke async operation is complete. |
