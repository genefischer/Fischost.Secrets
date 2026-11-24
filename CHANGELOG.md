# Changelog

## 2.0.0 (2026-11-24)

- New `AddFischostSecrets(config, options)`: explicit (vault name, config key) map, fetch by exact name only,
  never lists the vault. Per-entry outcomes (`Loaded`, `NotFound`, `Denied`, `SignInFailed`, `Unreachable`, `Error`),
  required and optional entries, older names as alternates, parallel fetch (max 8), timeout and capped retries.
- Credential selection is explicit: certificate, client secret, managed identity (opt-in with
  `FISCHOST_SECRETS_MANAGED_IDENTITY=1`; `AZURE_CLIENT_ID` alone is not enough). `DefaultAzureCredential` only in
  Development and only when asked. Partial or ambiguous `AZURE_*` sets (including certificate path plus client
  secret, or a certificate password without a path) fail loudly.
- Fail-fast: `ThrowIfRequiredProblems()` throws `FischostSecretsException` (names and statuses only) in every
  environment except Development. Development skips the vault by default. The environment is read from
  `ASPNETCORE_ENVIRONMENT` then `DOTNET_ENVIRONMENT`; it is Development only if every variable set says so.
  Apps should pass `builder.Environment.EnvironmentName`.
- Whitespace-only values count as NotFound. Alternates must not collide with any name or alternate in the map.
- `StartupTimeout` (default 30 s) bounds the whole load; `RefreshInterval` must be at least 1 second;
  `OnRefreshProblem` reports failed refreshes; a throwing change handler cannot break refresh.
- The legacy class is `[Obsolete]`: consumers that treat warnings as errors must suppress CS0618 until they
  migrate. It keeps its old credential fallback and is for migration only, but its messages and diagnostics no
  longer include the vault URL or inner exception text.
- NuGetAudit is on (vulnerable dependencies warn; low severity does not fail the build).
- `SecretsLoadResult`: `Summary()`, `Report(ILogger)`, `Diagnostics()`. No secret value, length, full URL or exception message is ever included.
- Optional `RefreshInterval`; a failed refresh keeps the last good values.
- Static `Secrets` class kept under `[Obsolete]`; `TryGet` now returns false when not initialised (was: threw).
- Solution is now `Fischost.Secrets.slnx` with `src/` and `tests/`; central package versions; CI workflow (build, test, pack; no publish).
- Dependencies: Azure.Identity 1.21.0, Azure.Security.KeyVault.Secrets 4.12.0, Microsoft.Extensions.* 10.0.x.

## 1.x

- Static `Secrets` helper (`InitFromEnv`, `InitWithClientSecret`, `Get`, `TryGet`, `DumpDiagnostics`).
