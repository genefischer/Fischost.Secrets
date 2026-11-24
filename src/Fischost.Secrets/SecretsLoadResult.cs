using Microsoft.Extensions.Logging;

namespace Fischost.Secrets;

/// <summary>
/// What a load did. Safe to log and print: secret names, statuses, the vault host and variable NAMES only.
/// </summary>
public sealed class SecretsLoadResult
{
    private readonly IReadOnlyList<string> _requiredNames;
    private readonly IReadOnlyDictionary<string, bool> _varsSet;
    private volatile IReadOnlyList<SecretOutcome> _refreshProblems = Array.Empty<SecretOutcome>();
    private long _lastRefreshTicks;

    internal SecretsLoadResult(
        string app, string environmentName, string? vaultHost, CredentialMode mode,
        IReadOnlyList<SecretOutcome> outcomes, string? skipReason, string? credentialProblem,
        IReadOnlyList<string> requiredNames, IReadOnlyDictionary<string, bool> varsSet)
    {
        App = app; EnvironmentName = environmentName; VaultHost = vaultHost; CredentialMode = mode;
        Outcomes = outcomes; SkipReason = skipReason; CredentialProblem = credentialProblem;
        _requiredNames = requiredNames; _varsSet = varsSet;
    }

    public string App { get; }
    public string EnvironmentName { get; }
    /// <summary>Host only, never the full URL.</summary>
    public string? VaultHost { get; }
    public CredentialMode CredentialMode { get; }
    public IReadOnlyList<SecretOutcome> Outcomes { get; }
    public bool Skipped => SkipReason is not null;
    /// <summary>"no vault url" or "development"; null when the vault was used.</summary>
    public string? SkipReason { get; }
    /// <summary>Why no credential could be made: variable names only, never values.</summary>
    public string? CredentialProblem { get; }

    /// <summary>Problems seen by the most recent refresh (empty when it was clean or none ran).</summary>
    public IReadOnlyList<SecretOutcome> RefreshProblems => _refreshProblems;
    public DateTimeOffset? LastRefreshUtc => _lastRefreshTicks == 0 ? null : new DateTimeOffset(Interlocked.Read(ref _lastRefreshTicks), TimeSpan.Zero);

    internal void RecordRefresh(IReadOnlyList<SecretOutcome> problems, DateTimeOffset when)
    {
        _refreshProblems = problems;
        Interlocked.Exchange(ref _lastRefreshTicks, when.UtcTicks);
    }

    /// <summary>Required entries that did not load (all required entries when the load was skipped).</summary>
    public IReadOnlyList<string> RequiredMissing =>
        Skipped ? _requiredNames : Outcomes.Where(o => o.Required && o.Status != SecretStatus.Loaded).Select(o => o.VaultName).ToArray();

    private IEnumerable<(string Name, string Why)> RequiredProblems() =>
        Skipped
            ? _requiredNames.Select(n => (n, SkipReason!))
            : Outcomes.Where(o => o.Required && o.Status != SecretStatus.Loaded).Select(o => (o.VaultName, o.Status.ToString()));

    /// <summary>
    /// Throws when a required secret is not loaded, but only in Production. Other environments never throw.
    /// Call after <see cref="Report"/> so the log has the details first.
    /// </summary>
    public void ThrowIfRequiredProblems()
    {
        if (!EnvironmentNames.IsProduction(EnvironmentName)) return;
        var problems = RequiredProblems().ToList();
        if (problems.Count == 0) return;
        var msg = $"{App}: required secrets not loaded: " + string.Join(", ", problems.Select(p => $"{p.Name} ({p.Why})"));
        if (CredentialProblem is not null) msg += $"; credential problem: {CredentialProblem}";
        throw new FischostSecretsException(msg);
    }

    private static string Phrase(SecretStatus s) => s switch
    {
        SecretStatus.NotFound => "not found",
        SecretStatus.Denied => "denied",
        SecretStatus.SignInFailed => "sign-in failed",
        SecretStatus.Unreachable => "unreachable",
        _ => "error",
    };

    /// <summary>One line, for example: <c>Upkeepify secrets: 11 loaded, 1 optional not found (Weather--ApiKey), 0 required problems</c>.</summary>
    public string Summary()
    {
        if (Skipped)
        {
            var s = $"{App} secrets: skipped ({SkipReason})";
            if (_requiredNames.Count > 0) s += $", {_requiredNames.Count} required missing ({string.Join(", ", _requiredNames)})";
            return s;
        }
        var parts = new List<string> { $"{Outcomes.Count(o => o.Status == SecretStatus.Loaded)} loaded" };
        foreach (var g in Outcomes.Where(o => !o.Required && o.Status != SecretStatus.Loaded).GroupBy(o => o.Status).OrderBy(g => g.Key))
            parts.Add($"{g.Count()} optional {Phrase(g.Key)} ({string.Join(", ", g.Select(o => o.VaultName))})");
        var req = Outcomes.Where(o => o.Required && o.Status != SecretStatus.Loaded).ToList();
        parts.Add(req.Count == 0
            ? "0 required problems"
            : $"{req.Count} required problems ({string.Join(", ", req.Select(o => $"{o.VaultName}: {o.Status}"))})");
        var line = $"{App} secrets: {string.Join(", ", parts)}";
        if (CredentialProblem is not null) line += $"; credential problem: {CredentialProblem}";
        return line;
    }

    /// <summary>Writes the summary and one line per problem. Never a value.</summary>
    public void Report(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        bool requiredBad = RequiredProblems().Any();
        bool optionalBad = Outcomes.Any(o => o.Status != SecretStatus.Loaded);
        var level = requiredBad ? LogLevel.Error : optionalBad || CredentialProblem is not null ? LogLevel.Warning : LogLevel.Information;
        logger.Log(level, "{Summary}", Summary());
        foreach (var o in Outcomes.Where(o => o.Status != SecretStatus.Loaded))
            logger.Log(o.Required ? LogLevel.Error : LogLevel.Warning,
                "Secret {SecretName} not loaded: {Status}{Http}{Required}",
                o.VaultName, o.Status, o.HttpStatus is { } h ? $" (HTTP {h})" : "", o.Required ? " [required]" : "");
    }

    /// <summary>Safe dump for a startup log: environment, vault host, credential mode, variable names set (Y/N), counts. No values.</summary>
    public string Diagnostics()
    {
        var lines = new List<string>
        {
            $"App: {App}",
            $"Environment: {EnvironmentName}",
            $"Vault host: {VaultHost ?? "(none)"}",
            $"Credential mode: {CredentialMode}",
            "Variables set: " + string.Join(", ", _varsSet.Select(kv => $"{kv.Key}={(kv.Value ? "Y" : "N")}")),
        };
        if (Skipped) lines.Add($"Skipped: {SkipReason}");
        if (CredentialProblem is not null) lines.Add($"Credential problem: {CredentialProblem}");
        lines.Add($"Counts: {Outcomes.Count} asked, {Outcomes.Count(o => o.Status == SecretStatus.Loaded)} loaded, " +
                  $"{Outcomes.Count(o => o.Status != SecretStatus.Loaded)} not loaded, {_requiredNames.Count} required");
        return string.Join(Environment.NewLine, lines);
    }

    public override string ToString() => Summary();
}
