# Fischost.Secrets

Loads one app's own secrets from Azure Key Vault into `IConfiguration`, by exact name, from an explicit map.
.NET 10. Version 2 replaces the static `Secrets` helper (still shipped, obsolete).

## Quick start

```csharp
var result = builder.Configuration.AddFischostSecrets(o =>
{
    o.App = "Upkeepify";
    o.Add("Upkeepify-DBConnectionString", "ConnectionStrings:Default", required: true);
    o.Add("Upkeepify-Weather--ApiKey", "Weather:ApiKey");
});
result.Report(app.Logger);            // after Build(); or use any ILogger
result.ThrowIfRequiredProblems();     // Production only: stops startup if a required secret is not loaded
```

The vault wins: values are added as the last configuration source, over `appsettings.json`.

## Rules

- **Naming:** every secret is `<App>-<Name>` (for example `Upkeepify-DBConnectionString`). Never reuse another
  app's secret. Names are 1-127 characters: letters, digits, hyphens. Anything else throws `ArgumentException`.
- **Explicit map, never list.** Each app's identity can read only its own secrets. The library fetches by exact
  name and has no code path that lists the vault; listing would be denied and would expose other apps' names.
- **Secret values never appear** in a report, log line, exception, summary or diagnostics. Outcomes carry the
  secret name, a status, an HTTP status and an exception type name. The vault is shown by host only.

## Options

| Option | Default |
|---|---|
| `App` (required, reports only) | |
| `Add(vaultName, configKey, required = false, params alternates)` | |
| `VaultUrl` | env `KEYVAULT_URL` |
| `RequestTimeout` | 10 s |
| `MaxRetries` | 2 (cap 5) |
| `RefreshInterval` | null (read once) |
| `EnvironmentName` | env `DOTNET_ENVIRONMENT`, then `ASPNETCORE_ENVIRONMENT`, else `Production` |
| `AllowVaultInDevelopment` | false |
| `AllowDefaultAzureCredentialInDevelopment` | false |

Duplicate vault names or config keys throw `ArgumentException` when added.
`alternates` are older vault names tried, in order, only when the first name is NotFound.

## Environment variables (names only)

| Name | Meaning |
|---|---|
| `KEYVAULT_URL` | The vault address. |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | Service-principal sign-in. |
| `AZURE_CLIENT_CERTIFICATE_PATH` (+ tenant and client id), `AZURE_CLIENT_CERTIFICATE_PASSWORD` (optional) | Certificate sign-in. |
| `FISCHOST_SECRETS_MANAGED_IDENTITY` | `1` selects the system-assigned managed identity. |
| `DOTNET_ENVIRONMENT`, `ASPNETCORE_ENVIRONMENT` | Environment name. |

## Credential order

1. Certificate path set: needs tenant and client id, then `ClientCertificateCredential`.
2. Tenant, client id and client secret all set: `ClientSecretCredential`.
3. Client id alone: user-assigned `ManagedIdentityCredential`.
4. No `AZURE_*` variables and `FISCHOST_SECRETS_MANAGED_IDENTITY=1` (not Development): system-assigned identity.
5. Development only, with both `AllowVaultInDevelopment` and `AllowDefaultAzureCredentialInDevelopment`: `DefaultAzureCredential`.
6. Anything else is a failure. `DefaultAzureCredential` is never used outside Development.

A partial set (for example tenant and client id but no secret, or a certificate path without a tenant) is a
hard failure: every entry becomes `SignInFailed` and `CredentialProblem` names the missing variable names.

## Production fail-fast, Development skip

- `AddFischostSecrets` never throws for missing secrets, so you can log first. Call `Report(logger)` then
  `ThrowIfRequiredProblems()`. It throws `FischostSecretsException` (names and statuses only) when a
  `required` entry is not `Loaded`, **only in Production**. Other environments never throw.
- No vault URL: the load is skipped (`SkipReason = "no vault url"`). If any entry is required and the
  environment is Production, `ThrowIfRequiredProblems` still throws.
- Environment `Development`: the vault is skipped (nothing fetched, no credential created) unless
  `AllowVaultInDevelopment`. Use user-secrets or `appsettings.Development.json` there.

## Statuses and report

`Loaded`, `NotFound` (404 or empty value), `Denied` (403), `SignInFailed` (401 or credential problem),
`Unreachable` (timeout or transport), `Error`. One failing entry never stops the others.

```
Upkeepify secrets: 11 loaded, 1 optional not found (Weather--ApiKey), 0 required problems
```

`Report` logs that line (Error if a required entry failed, Warning for optional problems) plus one line per
problem. `Diagnostics()` adds environment, vault host, credential mode and which `AZURE_*` names are set (Y/N).

## Refresh

`RefreshInterval = TimeSpan.FromHours(6)` re-reads the map and reloads configuration when something changed.
A failed refresh keeps the last good values and records the problem in `result.RefreshProblems`; it never blanks a secret.

## Migrating from the static `Secrets` class

```csharp
// before                                      // after
Secrets.InitFromEnv();                          builder.Configuration.AddFischostSecrets(o => {
var k = Secrets.Get("StripeApiKey");                o.App = "HomeFixer";
                                                    o.Add("HomeFixer-Stripe--ApiKey", "Stripe:ApiKey", true, "StripeApiKey"); });
```

Put the new `<App>-<Name>` first and the legacy name as an alternate; once the old secret is retired, drop
the alternate. The old class is `[Obsolete]`; `TryGet` now returns false when not initialised.

## Build

`dotnet build -c Release`, `dotnet test -c Release` (all offline), `dotnet pack -c Release` (output in `artifacts/packages`).
