using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;

namespace Fischost.Secrets;

public static class FischostSecretsExtensions
{
    /// <summary>
    /// Loads the app's secrets from Key Vault, by exact name from the map, into configuration, added last so
    /// the vault wins. Does not throw for missing secrets: call <see cref="SecretsLoadResult.Report"/> and then
    /// <see cref="SecretsLoadResult.ThrowIfRequiredProblems"/>.
    /// </summary>
    public static SecretsLoadResult AddFischostSecrets(this IConfigurationManager config, Action<FischostSecretsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(configure);
        var options = new FischostSecretsOptions();
        configure(options);
        if (string.IsNullOrWhiteSpace(options.App))
            throw new ArgumentException("FischostSecretsOptions.App is required.", nameof(configure));

        var env = options.EnvironmentName;
        var read = options.EnvironmentReader;
        var varsSet = CredentialSelector.ReportedNames.ToDictionary(n => n, n => !string.IsNullOrWhiteSpace(read(n)));
        var requiredNames = options.Entries.Where(e => e.Required).Select(e => e.VaultName).ToArray();

        SecretsLoadResult Skip(string reason, string? host = null) =>
            new(options.App, env, host, CredentialMode.None, Array.Empty<SecretOutcome>(), reason, null, requiredNames, varsSet);

        if (EnvironmentNames.IsDevelopment(env) && !options.AllowVaultInDevelopment)
            return Skip("development");

        var url = options.VaultUrl;
        if (string.IsNullOrWhiteSpace(url))
            return Skip("no vault url");

        SecretsLoadResult Failed(CredentialMode mode, SecretStatus status, string? host, string? problem, string? errorType) =>
            new(options.App, env, host, mode,
                options.Entries.Select(e => new SecretOutcome(e.VaultName, null, e.ConfigKey, status, e.Required, null, errorType)).ToArray(),
                null, problem, requiredNames, varsSet);

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            return Failed(CredentialMode.None, SecretStatus.Error, null, "vault url is not a valid https address", "InvalidVaultUrl");
        var host = uri.Host;

        var plan = CredentialSelector.Choose(
            varsSet.Keys.ToDictionary(n => n, n => read(n), StringComparer.Ordinal), env, options);
        if (!plan.IsOk)
            return Failed(CredentialMode.None, SecretStatus.SignInFailed, host, plan.Problem, null);

        ISecretSource source;
        if (options.SecretSourceOverride is { } fake) source = fake;
        else
        {
            try
            {
                var credential = CredentialSelector.Create(plan.Mode, read);
                var clientOptions = new SecretClientOptions();
                clientOptions.Retry.MaxRetries = options.MaxRetries;
                clientOptions.Retry.Delay = TimeSpan.FromMilliseconds(300);
                clientOptions.Retry.MaxDelay = TimeSpan.FromSeconds(3);
                clientOptions.Retry.Mode = RetryMode.Exponential;
                clientOptions.Retry.NetworkTimeout = options.RequestTimeout;
                source = new KeyVaultSecretSource(new SecretClient(uri, credential, clientOptions));
            }
            catch (Exception ex)
            {
                return Failed(plan.Mode, SecretStatus.SignInFailed, host, "credential could not be created", ex.GetType().Name);
            }
        }

        var entries = options.Entries.ToArray();
        var timeout = options.RequestTimeout;
        Task<LoadBatch> Run(CancellationToken ct) => SecretsLoader.LoadAsync(entries, source, timeout, ct);
        var batch = Task.Run(() => Run(CancellationToken.None)).GetAwaiter().GetResult();

        var result = new SecretsLoadResult(options.App, env, host, plan.Mode, batch.Outcomes, null, null, requiredNames, varsSet);
        config.Add(new SecretsConfigurationSource(batch.Values, result, options.RefreshInterval is null ? null : Run, options.RefreshInterval));
        return result;
    }
}
