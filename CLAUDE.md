# Fischost.Secrets (shared library)

- .NET 10, central package versions in `Directory.Packages.props`. Public API: `AddFischostSecrets` in `src/Fischost.Secrets`.
- **Never log or return a secret value**, its length, the full vault URL, or an exception message. Names, statuses, vault host only.
- **Never list the vault.** `ISecretSource` has one method, `GetAsync(name)`. Each app's identity can read only its own secrets.
- Tests are offline: fake `ISecretSource`, fake variable dictionaries (`Fake.*`), no network, no real environment mutation, no real Azure objects.
- `DefaultAzureCredential` is never used outside Development. Partial `AZURE_*` sets are a hard failure.
- `AddFischostSecrets` does not throw; the app calls `Report` then `ThrowIfRequiredProblems` (Production only).
- The static `Secrets` class in `Legacy/` is obsolete and frozen; do not extend it.
- PowerShell scripts are ASCII only.
- Pack: `dotnet pack -c Release` writes `artifacts/packages/Fischost.Secrets.<version>.nupkg` (+ snupkg). Check with `tools/consumer-test.sh`. CI never publishes; publishing is the owner's decision.
- Bump `VersionPrefix` in `Directory.Build.props` and add a `CHANGELOG.md` entry with any API change.
