using Azure;
using Azure.Security.KeyVault.Secrets;

namespace Fischost.Secrets;

/// <summary>A fetched value. Never printed: ToString does not show it.</summary>
internal sealed class SecretFetch
{
    public SecretFetch(string? value) => Value = value;
    public string? Value { get; }
    public override string ToString() => nameof(SecretFetch);
}

/// <summary>
/// The only door to the vault. One method, one exact name. There is deliberately no way to list.
/// Failures are thrown (RequestFailedException etc.); the loader maps them.
/// </summary>
internal interface ISecretSource
{
    Task<SecretFetch> GetAsync(string name, CancellationToken ct);
}

internal sealed class KeyVaultSecretSource : ISecretSource
{
    private readonly SecretClient _client;
    public KeyVaultSecretSource(SecretClient client) => _client = client;

    public async Task<SecretFetch> GetAsync(string name, CancellationToken ct)
    {
        Response<KeyVaultSecret> r = await _client.GetSecretAsync(name, cancellationToken: ct).ConfigureAwait(false);
        return new SecretFetch(r.Value.Value);
    }
}
