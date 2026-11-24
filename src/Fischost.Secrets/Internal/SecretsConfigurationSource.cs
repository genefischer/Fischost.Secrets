using System.Diagnostics;
using Microsoft.Extensions.Configuration;

namespace Fischost.Secrets;

/// <summary>
/// An in-memory source that can re-read the vault. With no refresh it behaves like AddInMemoryCollection.
/// One source builds one provider, however many times Build is called, so no second timer can appear.
/// </summary>
internal sealed class SecretsConfigurationSource : IConfigurationSource
{
    private SecretsConfigurationProvider? _provider;
    private readonly object _gate = new();

    public SecretsConfigurationSource(
        Dictionary<string, string> initial, SecretsLoadResult result,
        Func<CancellationToken, Task<LoadBatch>>? reload, TimeSpan? interval, Action<SecretOutcome>? onProblem = null)
    {
        Initial = initial; Result = result; Reload = reload; Interval = interval; OnProblem = onProblem;
    }

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public Dictionary<string, string> Initial { get; }
    public SecretsLoadResult Result { get; }
    public Func<CancellationToken, Task<LoadBatch>>? Reload { get; }
    public TimeSpan? Interval { get; }
    public Action<SecretOutcome>? OnProblem { get; }

    public IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        lock (_gate) return _provider ??= new SecretsConfigurationProvider(this);
    }

    public override string ToString() => $"{nameof(SecretsConfigurationSource)}({Initial.Count} values)";
}

internal sealed class SecretsConfigurationProvider : ConfigurationProvider, IDisposable
{
    private readonly SecretsConfigurationSource _source;
    private readonly Timer? _timer;
    private readonly SemaphoreSlim _busy = new(1, 1);
    private readonly CancellationTokenSource _stop = new();
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private Dictionary<string, string?> _current;
    private volatile bool _disposed;

    public SecretsConfigurationProvider(SecretsConfigurationSource source)
    {
        _source = source;
        _current = new Dictionary<string, string?>(source.Initial.Select(kv => new KeyValuePair<string, string?>(kv.Key, kv.Value)),
            StringComparer.OrdinalIgnoreCase);
        if (source.Interval is { } iv && source.Reload is not null)
            _timer = new Timer(_ => _ = RefreshAsync(), null, iv, iv);
    }

    internal bool TimerRunning => _timer is not null && !_disposed;
    internal bool IsDisposed => _disposed;

    public override void Load() => Data = new Dictionary<string, string?>(_current, StringComparer.OrdinalIgnoreCase);

    public override string ToString() => nameof(SecretsConfigurationProvider);

    /// <summary>
    /// Re-reads the vault. Values that load replace the old ones; anything that fails keeps its last good value.
    /// Problems are recorded on the result and passed to OnRefreshProblem. Never throws.
    /// </summary>
    internal async Task RefreshAsync()
    {
        if (_disposed || _source.Reload is null) return;
        bool entered;
        try { entered = await _busy.WaitAsync(0).ConfigureAwait(false); }
        catch (ObjectDisposedException) { return; }
        if (!entered) return;
        try
        {
            if (_disposed) return;
            LoadBatch batch;
            try { batch = await _source.Reload(_stop.Token).ConfigureAwait(false); }
            catch (Exception ex)
            {
                var o = new SecretOutcome("(refresh)", null, "(refresh)", SecretStatus.Error, false, null, ex.GetType().Name);
                _source.Result.RecordRefresh([o], DateTimeOffset.UtcNow);
                Notify(o);
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
            var problems = batch.Outcomes.Where(o => o.Status != SecretStatus.Loaded).ToArray();
            _source.Result.RecordRefresh(problems, DateTimeOffset.UtcNow);
            foreach (var p in problems) Notify(p);
            if (changed)
            {
                Data = new Dictionary<string, string?>(next, StringComparer.OrdinalIgnoreCase);
                try { OnReload(); }
                catch { /* a faulty change handler must not stop refreshing */ }
            }
        }
        finally
        {
            try { _busy.Release(); } catch (ObjectDisposedException) { }
        }
    }

    private void Notify(SecretOutcome o)
    {
        try { _source.OnProblem?.Invoke(o); }
        catch { /* the callback must never break refresh */ }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _timer?.Dispose();
        try { _stop.Cancel(); } catch { }
        _stop.Dispose();
        _busy.Dispose();
    }
}
