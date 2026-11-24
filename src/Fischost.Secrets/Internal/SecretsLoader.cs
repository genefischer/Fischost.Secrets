using System.Diagnostics;
using System.Net.Http;
using System.Net.Sockets;
using Azure;
using Azure.Identity;

namespace Fischost.Secrets;

internal sealed record LoadBatch(IReadOnlyList<SecretOutcome> Outcomes, [property: DebuggerBrowsable(DebuggerBrowsableState.Never)] Dictionary<string, string> Values)
{
    // The default record ToString would print members; keep values out of every text form.
    public override string ToString() => $"{nameof(LoadBatch)}({Outcomes.Count} outcomes, {Values.Count} values)";
}

/// <summary>Fetches each map entry by exact name. One failing entry never stops the others.</summary>
internal static class SecretsLoader
{
    public const int MaxParallel = 8;

    public static async Task<LoadBatch> LoadAsync(
        IReadOnlyList<FischostSecretsOptions.Entry> entries, ISecretSource source, TimeSpan timeout, TimeSpan startupTimeout, CancellationToken ct)
    {
        // Not disposed on purpose: entries abandoned at the deadline may still touch it.
        var gate = new SemaphoreSlim(MaxParallel);
        using var deadlineCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = deadlineCts.Token;
        var tasks = entries.Select(async e =>
        {
            await gate.WaitAsync(token).ConfigureAwait(false);
            try { return await LoadOneAsync(e, source, timeout, token).ConfigureAwait(false); }
            finally { gate.Release(); }
        }).ToArray();

        var all = Task.WhenAll(tasks);
        using (var delayCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            var winner = await Task.WhenAny(all, Task.Delay(startupTimeout, delayCts.Token)).ConfigureAwait(false);
            delayCts.Cancel();
            if (winner != all) deadlineCts.Cancel(); // stop cooperative stragglers
        }
        ct.ThrowIfCancellationRequested();

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var outcomes = new List<SecretOutcome>(entries.Count);
        for (int i = 0; i < tasks.Length; i++)
        {
            var e = entries[i];
            if (tasks[i].IsCompletedSuccessfully)
            {
                var (outcome, value) = tasks[i].Result;
                outcomes.Add(outcome);
                if (value is not null) values[outcome.ConfigKey] = value;
            }
            else
            {
                _ = tasks[i].ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
                outcomes.Add(new SecretOutcome(e.VaultName, null, e.ConfigKey, SecretStatus.Unreachable, e.Required, null, "StartupTimeout"));
            }
        }
        return new LoadBatch(outcomes, values);
    }

    private static async Task<(SecretOutcome, string?)> LoadOneAsync(
        FischostSecretsOptions.Entry e, ISecretSource source, TimeSpan timeout, CancellationToken ct)
    {
        Attempt? failure = null;
        foreach (var name in new[] { e.VaultName }.Concat(e.Alternates))
        {
            var a = await TryFetchAsync(source, name, timeout, ct).ConfigureAwait(false);
            if (a.Status == SecretStatus.Loaded)
                return (new SecretOutcome(e.VaultName, name, e.ConfigKey, SecretStatus.Loaded, e.Required), a.Value);
            if (a.Status == SecretStatus.NotFound)
            {
                failure ??= a;
                continue; // try the next older name
            }
            failure = a; // a real problem outranks "not found"; do not try alternates
            break;
        }
        failure ??= new Attempt(SecretStatus.NotFound, null, null, null);
        return (new SecretOutcome(e.VaultName, null, e.ConfigKey, failure.Status, e.Required, failure.Http, failure.ErrorType), null);
    }

    internal sealed record Attempt(SecretStatus Status, [property: DebuggerBrowsable(DebuggerBrowsableState.Never)] string? Value, int? Http, string? ErrorType)
    {
        public override string ToString() => $"{nameof(Attempt)}({Status})";
    }

    private static async Task<Attempt> TryFetchAsync(ISecretSource source, string name, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            var call = source.GetAsync(name, cts.Token);
            using var delayCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var winner = await Task.WhenAny(call, Task.Delay(timeout, delayCts.Token)).ConfigureAwait(false);
            if (winner != call)
            {
                // A source that ignores its token must not hold the app up.
                cts.Cancel();
                _ = call.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
                ct.ThrowIfCancellationRequested();
                return new Attempt(SecretStatus.Unreachable, null, null, "Timeout");
            }
            delayCts.Cancel();
            var f = await call.ConfigureAwait(false);
            return string.IsNullOrWhiteSpace(f.Value)
                ? new Attempt(SecretStatus.NotFound, null, null, null)
                : new Attempt(SecretStatus.Loaded, f.Value, null, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new Attempt(SecretStatus.Unreachable, null, null, "Timeout");
        }
        catch (RequestFailedException ex)
        {
            var type = ex.GetType().Name;
            return ex.Status switch
            {
                404 => new Attempt(SecretStatus.NotFound, null, 404, type),
                403 => new Attempt(SecretStatus.Denied, null, 403, type),
                401 => new Attempt(SecretStatus.SignInFailed, null, 401, type),
                0 => new Attempt(SecretStatus.Unreachable, null, null, type),
                _ => new Attempt(SecretStatus.Error, null, ex.Status, type),
            };
        }
        catch (Exception ex) when (ex is AuthenticationFailedException or CredentialUnavailableException)
        {
            return new Attempt(SecretStatus.SignInFailed, null, null, ex.GetType().Name);
        }
        catch (Exception ex) when (ex is HttpRequestException or TimeoutException or IOException or SocketException)
        {
            return new Attempt(SecretStatus.Unreachable, null, null, ex.GetType().Name);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new Attempt(SecretStatus.Error, null, null, ex.GetType().Name);
        }
    }
}
