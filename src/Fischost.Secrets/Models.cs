namespace Fischost.Secrets;

/// <summary>How the vault credential was (or would be) created.</summary>
public enum CredentialMode
{
    None,
    Certificate,
    ClientSecret,
    ManagedIdentity,
    DefaultAzure,
}

/// <summary>What happened when one secret was asked for.</summary>
public enum SecretStatus
{
    Loaded,
    /// <summary>404, or an empty value.</summary>
    NotFound,
    /// <summary>403: the app's identity has no read access to this secret.</summary>
    Denied,
    /// <summary>401, or the credential could not be created or used.</summary>
    SignInFailed,
    /// <summary>Timeout or transport failure.</summary>
    Unreachable,
    Error,
}

/// <summary>
/// The result for one map entry. Holds no secret value, no value length, no URL and no exception message.
/// </summary>
/// <param name="VaultName">The name asked first.</param>
/// <param name="UsedName">The name that actually loaded (an alternate, perhaps); null when not loaded.</param>
/// <param name="ConfigKey">Where the value went in configuration.</param>
/// <param name="Status">What happened.</param>
/// <param name="Required">Whether the app cannot start in Production without it.</param>
/// <param name="HttpStatus">HTTP status when the vault answered with one.</param>
/// <param name="ErrorType">Exception type name only.</param>
public sealed record SecretOutcome(
    string VaultName,
    string? UsedName,
    string ConfigKey,
    SecretStatus Status,
    bool Required,
    int? HttpStatus = null,
    string? ErrorType = null);

/// <summary>Thrown by <see cref="SecretsLoadResult.ThrowIfRequiredProblems"/>. Names and statuses only.</summary>
public sealed class FischostSecretsException : Exception
{
    public FischostSecretsException(string message) : base(message) { }
}
