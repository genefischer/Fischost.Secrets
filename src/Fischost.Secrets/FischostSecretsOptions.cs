using System.Text.RegularExpressions;

namespace Fischost.Secrets;

/// <summary>Which secrets one app asks for, and how. Fetch is always by exact name from this map.</summary>
public sealed partial class FischostSecretsOptions
{
    [GeneratedRegex(@"\A[0-9A-Za-z-]{1,127}\z")]
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

    private TimeSpan? _refresh;
    private TimeSpan _startup = TimeSpan.FromSeconds(30);

    /// <summary>Null: read once. Otherwise re-read on this interval (at least 1 second); a failed refresh keeps the last good values.</summary>
    public TimeSpan? RefreshInterval
    {
        get => _refresh;
        set => _refresh = value is null || value >= TimeSpan.FromSeconds(1) ? value : throw new ArgumentOutOfRangeException(nameof(value), "RefreshInterval must be null or at least 1 second.");
    }

    /// <summary>Bounds the whole startup load (default 30 s; must be at least RequestTimeout). Entries unfinished at the deadline become Unreachable (ErrorType StartupTimeout).</summary>
    public TimeSpan StartupTimeout
    {
        get => _startup;
        set => _startup = value > TimeSpan.Zero ? value : throw new ArgumentOutOfRangeException(nameof(value));
    }

    /// <summary>Called for each secret that failed to refresh (the last good value stays in place). Exceptions from it are swallowed.</summary>
    public Action<SecretOutcome>? OnRefreshProblem { get; set; }

    /// <summary>
    /// Default: ASPNETCORE_ENVIRONMENT, then DOTNET_ENVIRONMENT, else "Production". It counts as Development only
    /// if every one of those variables that is set says Development; any disagreement is not Development.
    /// Apps should pass the host's own name: <c>o.EnvironmentName = builder.Environment.EnvironmentName</c>.
    /// </summary>
    public string EnvironmentName
    {
        get
        {
            if (_envName is not null) return _envName;
            var set = new[] { EnvironmentReader("ASPNETCORE_ENVIRONMENT"), EnvironmentReader("DOTNET_ENVIRONMENT") }
                .Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v!.Trim()).ToArray();
            if (set.Length == 0) return "Production";
            return set.FirstOrDefault(v => !EnvironmentNames.IsDevelopment(v)) ?? set[0];
        }
        set => _envName = value;
    }

    public bool AllowVaultInDevelopment { get; set; }
    public bool AllowDefaultAzureCredentialInDevelopment { get; set; }

    /// <summary>Test seam.</summary>
    internal ISecretSource? SecretSourceOverride { get; set; }

    /// <summary>Test seam: replaces the HTTP transport of the real SecretClient.</summary>
    internal Azure.Core.Pipeline.HttpPipelineTransport? ClientTransport { get; set; }

    /// <summary>Test seam: replaces the credential of the real SecretClient.</summary>
    internal Azure.Core.TokenCredential? CredentialOverride { get; set; }

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
        bool Taken(string n) => _entries.Any(e => Same(e.VaultName, n) || e.Alternates.Any(x => Same(x, n)));
        if (Taken(vaultName))
            throw new ArgumentException($"Vault name '{vaultName}' is already in the map (as a name or an alternate).", nameof(vaultName));
        if (_entries.Any(e => Same(e.ConfigKey, configKey)))
            throw new ArgumentException($"Config key '{configKey}' is already in the map.", nameof(configKey));
        for (int i = 0; i < alternates.Length; i++)
        {
            if (Same(alternates[i], vaultName) || Taken(alternates[i]) || alternates.Take(i).Any(x => Same(x, alternates[i])))
                throw new ArgumentException($"Alternate '{alternates[i]}' is already used elsewhere in the map.", nameof(alternates));
        }
        _entries.Add(new Entry(vaultName, configKey, required, alternates.ToArray()));
        return this;
    }

    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static void CheckName(string name, string param)
    {
        if (name is null || !NameRule().IsMatch(name))
            throw new ArgumentException("A Key Vault secret name is 1-127 characters: letters, digits and hyphens only.", param);
    }
}
