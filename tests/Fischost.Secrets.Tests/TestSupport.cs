using Azure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Fischost.Secrets.Tests;

internal static class Fake
{
    public const string Value = "FAKE-VALUE-12345";
    public const string VaultUrl = "https://fake-vault.vault.azure.net/";
    public const string Host = "fake-vault.vault.azure.net";

    /// <summary>A complete, fake client-secret variable set. Not real, never leaves the process.</summary>
    public static Dictionary<string, string?> ClientSecretVars() => new()
    {
        ["AZURE_TENANT_ID"] = "fake-tenant",
        ["AZURE_CLIENT_ID"] = "fake-client",
        ["AZURE_CLIENT_SECRET"] = "fake-client-pw",
    };

    public static Func<string, string?> Reader(IDictionary<string, string?> vars) =>
        n => vars.TryGetValue(n, out var v) ? v : null;

    /// <summary>Options wired for an offline Production run with the given source.</summary>
    public static Action<FischostSecretsOptions> Opts(ISecretSource? source, Action<FischostSecretsOptions> more, IDictionary<string, string?>? vars = null) => o =>
    {
        o.App = "TestApp";
        o.EnvironmentReader = Reader(vars ?? ClientSecretVars());
        o.VaultUrl = VaultUrl;
        o.EnvironmentName = "Production";
        o.SecretSourceOverride = source;
        more(o);
    };

    public static SecretsLoadResult Load(ConfigurationManager cfg, ISecretSource? source, Action<FischostSecretsOptions> more, IDictionary<string, string?>? vars = null) =>
        cfg.AddFischostSecrets(Opts(source, more, vars));
}

/// <summary>A scripted vault. Records every name asked and the highest concurrency seen.</summary>
internal sealed class FakeSource : ISecretSource
{
    private readonly Dictionary<string, Func<CancellationToken, Task<string?>>> _behaviors = new();
    private int _now, _max;
    public List<string> Asked { get; } = new();
    public int MaxConcurrent => _max;
    public TimeSpan Delay { get; set; }

    public FakeSource Value(string name, string? value) { _behaviors[name] = _ => Task.FromResult(value); return this; }
    public FakeSource Fail(string name, Exception ex) { _behaviors[name] = _ => throw ex; return this; }
    public FakeSource Http(string name, int status) => Fail(name, new RequestFailedException(status, "msg-with-FAKE-VALUE-12345"));
    public FakeSource Hang(string name) { _behaviors[name] = async ct => { await Task.Delay(Timeout.Infinite, ct); return null; }; return this; }
    public FakeSource Custom(string name, Func<CancellationToken, Task<string?>> f) { _behaviors[name] = f; return this; }

    public async Task<SecretFetch> GetAsync(string name, CancellationToken ct)
    {
        lock (Asked) Asked.Add(name);
        var n = Interlocked.Increment(ref _now);
        int seen;
        do { seen = _max; } while (n > seen && Interlocked.CompareExchange(ref _max, n, seen) != seen);
        try
        {
            if (Delay > TimeSpan.Zero) await Task.Delay(Delay, ct);
            if (!_behaviors.TryGetValue(name, out var b)) throw new RequestFailedException(404, "not found");
            return new SecretFetch(await b(ct));
        }
        finally { Interlocked.Decrement(ref _now); }
    }
}

internal sealed class TestLogger : ILogger
{
    public List<(LogLevel Level, string Message)> Lines { get; } = new();
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
        Lines.Add((logLevel, formatter(state, exception) + (exception is null ? "" : " " + exception)));
    public string All => string.Join("\n", Lines.Select(l => l.Message));
}
