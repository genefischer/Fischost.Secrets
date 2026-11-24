using Microsoft.Extensions.Configuration;

namespace Fischost.Secrets;

/// <summary>An in-memory source that can re-read the vault. With no refresh it behaves like AddInMemoryCollection.</summary>
internal sealed class SecretsConfigurationSource : IConfigurationSource
{
    public SecretsConfigurationSource(
        Dictionary<string, string> initial, SecretsLoadResult result,
        Func<CancellationToken, Task<LoadBatch>>? reload, TimeSpan? interval)
    {
        Initial = initial; Result = result; Reload = reload; Interval = interval;
    }

    public Dictionary<string, string> Initial { get; }
    public SecretsLoadResult Result { get; }
    public Func<CancellationToken, Task<LoadBatch>>? Reload { get; }
    public TimeSpan? Interval { get; }

    public IConfigurationProvider Build(IConfigurationBuilder builder) => new SecretsConfigurationProvider(this);
}

internal sealed class SecretsConfigurationProvider : ConfigurationProvider, IDisposable
{
    private readonly SecretsConfigurationSource _source;
    private readonly Timer? _timer;
    private readonly SemaphoreSlim _busy = new(1, 1);
    private readonly CancellationTokenSource _stop = new();
    private Dictionary<string, string?> _current;

    public SecretsConfigurationProvider(SecretsConfigurationSource source)
    {
        _source = source;
        _current = new Dictionary<string, string?>(source.Initial.Select(kv => new KeyValuePair<string, string?>(kv.Key, kv.Value)),
            StringComparer.OrdinalIgnoreCase);
        if (source.Interval is { } iv && source.Reload is not null)
            _timer = new Timer(_ => _ = RefreshAsync(), null, iv, iv);
    }

    public override void Load() => Data = new Dictionary<string, string?>(_current, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Re-reads the vault. Values that load replace the old ones; anything that fails keeps its last good value.
    /// Problems are recorded on the result. Never throws.
    /// </summary>
    internal async Task RefreshAsync()
    {
        if (_source.Reload is null || !await _busy.WaitAsync(0).ConfigureAwait(false)) return;
        try
        {
            LoadBatch batch;
            try { batch = await _source.Reload(_stop.Token).ConfigureAwait(false); }
            catch (Exception ex)
            {
                _source.Result.RecordRefresh(
                    [new SecretOutcome("(refresh)", null, "(refresh)", SecretStatus.Error, false, null, ex.GetType().Name)],
                    DateTimeOffset.UtcNow);
                return;
            }
            var next = new Dictionary<string, string?>(_current, StringComparer.OrdinalIgnoreCase);
            bool changed = false;
            foreach (var (key, value) in batch.Values)
            {
                if (!next.TryGetValue(key, out var old) || !string.Equals(old, value, StringComparison.Ordinal))
                {
                    next[key] = value;
                    changed = true;
                }
            }
            _current = next;
            _source.Result.RecordRefresh(batch.Outcomes.Where(o => o.Status != SecretStatus.Loaded).ToArray(), DateTimeOffset.UtcNow);
            if (changed)
            {
                Data = new Dictionary<string, string?>(next, StringComparer.OrdinalIgnoreCase);
                OnReload();
            }
        }
        finally { _busy.Release(); }
    }

    public void Dispose()
    {
        _stop.Cancel();
        _timer?.Dispose();
    }
}
