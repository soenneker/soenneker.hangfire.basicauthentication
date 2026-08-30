[![](https://img.shields.io/nuget/v/Soenneker.Hangfire.BasicAuthentication.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Hangfire.BasicAuthentication/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hangfire.basicauthentication/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.hangfire.basicauthentication/actions/workflows/publish-package.yml)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hangfire.basicauthentication/build-and-test.yml?style=for-the-badge&label=build)](https://github.com/soenneker/soenneker.hangfire.basicauthentication/actions/workflows/build-and-test.yml)
[![](https://img.shields.io/nuget/dt/Soenneker.Hangfire.BasicAuthentication.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Hangfire.BasicAuthentication/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hangfire.basicauthentication/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.hangfire.basicauthentication/actions/workflows/codeql.yml)

# Soenneker.Hangfire.BasicAuthentication

Protects a Hangfire dashboard with HTTP Basic authentication. The configured password is a PBKDF2 PHC record, so plaintext dashboard credentials do not need to be stored in application configuration.

## Installation

```bash
dotnet add package Soenneker.Hangfire.BasicAuthentication
```

## Configuration

```json
{
  "Hangfire": {
    "Username": "admin",
    "PasswordPhc": "<PBKDF2 PHC record>",
    "LocalAuthenticationBypassEnabled": false,
    "Url": "/hangfire"
  }
}
```

Generate the PHC value once and store it in a secret provider:

```csharp
using Soenneker.Hashing.Pbkdf2;

string passwordPhc = Pbkdf2HashingUtil.Hash("replace-with-a-strong-password");
```

## Registration and middleware order

```csharp
using Hangfire;
using Soenneker.Hangfire.BasicAuthentication;
using Soenneker.Hangfire.BasicAuthentication.Registrars;

builder.Services.AddHangfireBasicAuth();

app.UseHangfireAuthorized();

app.UseHangfireDashboard("/hangfire", new DashboardOptions
{
    Authorization = [new HangfireAuthorizationFilter()]
});
```

`UseHangfireAuthorized()` must appear before `UseHangfireDashboard()`, and `Hangfire:Url` must match the dashboard path. `HangfireAuthorizationFilter` deliberately allows Hangfire's internal authorization stage to continue because the preceding middleware performs the credential check; do not use that filter without the middleware.

Requests outside the configured dashboard path are unaffected. Matching requests without valid credentials receive `401 Unauthorized` and a `WWW-Authenticate: Basic` challenge.

Enable `LocalAuthenticationBypassEnabled` only when every request considered local by the application is trusted. Basic authentication must be served over HTTPS because credentials are encoded, not encrypted, in the request header.
