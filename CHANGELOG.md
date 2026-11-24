# Changelog

## 2.0.0 (2026-11-24)

- New `AddFischostSecrets(config, options)`: explicit (vault name, config key) map, fetch by exact name only,
  never lists the vault. Per-entry outcomes (`Loaded`, `NotFound`, `Denied`, `SignInFailed`, `Unreachable`, `Error`),
  required and optional entries, older names as alternates, parallel fetch (max 8), timeout and capped retries.
- Credential selection is explicit: certificate, client secret, user- or system-assigned managed identity.
  `DefaultAzureCredential` only in Development and only when asked. Partial `AZURE_*` sets fail loudly.
- Production fail-fast: `ThrowIfRequiredProblems()` throws `FischostSecretsException` (names and statuses only).
  Development skips the vault by default.
- `SecretsLoadResult`: `Summary()`, `Report(ILogger)`, `Diagnostics()`. No secret value, length, full URL or exception message is ever included.
- Optional `RefreshInterval`; a failed refresh keeps the last good values.
- Static `Secrets` class kept under `[Obsolete]`; `TryGet` now returns false when not initialised (was: threw).
- Solution is now `Fischost.Secrets.slnx` with `src/` and `tests/`; central package versions; CI workflow (build, test, pack; no publish).
- Dependencies: Azure.Identity 1.21.0, Azure.Security.KeyVault.Secrets 4.12.0, Microsoft.Extensions.* 10.0.x.

## 1.x

- Static `Secrets` helper (`InitFromEnv`, `InitWithClientSecret`, `Get`, `TryGet`, `DumpDiagnostics`).
