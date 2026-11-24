using System.Text.RegularExpressions;

namespace Fischost.Secrets;

/// <summary>Which secrets one app asks for, and how. Fetch is always by exact name from this map.</summary>
public sealed partial class FischostSecretsOptions
{
    [GeneratedRegex("^[0-9A-Za-z-]{1,127}$")]
    private static partial Regex NameRule();

    internal sealed record Entry(string VaultName, string ConfigKey, bool Required, string[] Alternates);

    private readonly List<Entry> _entries = new();
    private string? _vaultUrl;
    private bool _vaultUrlSet;
    private string? _envName;
    private TimeSpan _timeout = TimeSpan.FromSeconds(10);
    private int _retries = 2;

    /// <summary>Used only in reports.</summary>
    public string App { get; set; } = "";

    /// <summary>Default: environment variable KEYVAULT_URL. Set to empty to force "no vault".</summary>
    public string? VaultUrl
    {
        get => _vaultUrlSet ? _vaultUrl : EnvironmentReader("KEYVAULT_URL");
        set { _vaultUrl = value; _vaultUrlSet = true; }
    }

    public TimeSpan RequestTimeout
    {
        get => _timeout;
        set => _timeout = value > TimeSpan.Zero ? value : throw new ArgumentOutOfRangeException(nameof(value));
    }

    /// <summary>Retries per request; clamped to 0..5.</summary>
    public int MaxRetries { get => _retries; set => _retries = Math.Clamp(value, 0, 5); }

    /// <summary>Null: read once. Otherwise re-read on this interval; a failed refresh keeps the last good values.</summary>
    public TimeSpan? RefreshInterval { get; set; }

    /// <summary>Default: DOTNET_ENVIRONMENT, then ASPNETCORE_ENVIRONMENT, else "Production".</summary>
    public string EnvironmentName
    {
        get
        {
            if (_envName is not null) return _envName;
            var e = EnvironmentReader("DOTNET_ENVIRONMENT");
            if (string.IsNullOrWhiteSpace(e)) e = EnvironmentReader("ASPNETCORE_ENVIRONMENT");
            return string.IsNullOrWhiteSpace(e) ? "Production" : e.Trim();
        }
        set => _envName = value;
    }

    public bool AllowVaultInDevelopment { get; set; }
    public bool AllowDefaultAzureCredentialInDevelopment { get; set; }

    /// <summary>Test seam.</summary>
    internal ISecretSource? SecretSourceOverride { get; set; }

    /// <summary>Edge: where environment variables are read. Tests replace it.</summary>
    internal Func<string, string?> EnvironmentReader { get; set; } = Environment.GetEnvironmentVariable;

    internal IReadOnlyList<Entry> Entries => _entries;

    /// <summary>
    /// Adds one secret. <paramref name="alternates"/> are older vault names tried in order when the first is NotFound.
    /// </summary>
    public FischostSecretsOptions Add(string vaultName, string configKey, bool required = false, params string[] alternates)
    {
        CheckName(vaultName, nameof(vaultName));
        if (string.IsNullOrWhiteSpace(configKey))
            throw new ArgumentException("Config key is required.", nameof(configKey));
        alternates ??= [];
        foreach (var a in alternates) CheckName(a, nameof(alternates));
        if (_entries.Any(e => string.Equals(e.VaultName, vaultName, StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException($"Vault name '{vaultName}' is already in the map.", nameof(vaultName));
        if (_entries.Any(e => string.Equals(e.ConfigKey, configKey, StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException($"Config key '{configKey}' is already in the map.", nameof(configKey));
        _entries.Add(new Entry(vaultName, configKey, required,
            alternates.Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(a => !string.Equals(a, vaultName, StringComparison.OrdinalIgnoreCase)).ToArray()));
        return this;
    }

    private static void CheckName(string name, string param)
    {
        if (name is null || !NameRule().IsMatch(name))
            throw new ArgumentException("A Key Vault secret name is 1-127 characters: letters, digits and hyphens only.", param);
    }
}
