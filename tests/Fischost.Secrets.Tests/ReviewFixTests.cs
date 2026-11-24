#pragma warning disable CS0618 // legacy class

using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;

namespace Fischost.Secrets.Tests;

internal sealed class FakeCredential : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => new("fake-token", DateTimeOffset.UtcNow.AddHours(1));
    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => new(GetToken(requestContext, cancellationToken));
}

/// <summary>Canned vault over HttpClient: answers the key-vault auth challenge, records every request, then answers per test.</summary>
internal sealed class CannedVault : HttpMessageHandler
{
    private readonly object _gate = new();
    public List<(string Method, string Path)> Requests { get; } = new();
    public Func<string, CancellationToken, Task<HttpResponseMessage>> Respond { get; set; } = (_, _) => Task.FromResult(Json(404, "{}"));

    public HttpPipelineTransport Transport => new HttpClientTransport(new HttpClient(this));

    public static HttpResponseMessage Json(int status, string body) =>
        new((HttpStatusCode)status) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Secret(string name, string value) =>
        Json(200, $"{{\"value\":\"{value}\",\"id\":\"https://fake-vault.vault.azure.net/secrets/{name}/v1\",\"attributes\":{{\"enabled\":true}}}}");

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken ct) =>
        Task.Run(() => SendAsync(request, ct), ct).GetAwaiter().GetResult();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        lock (_gate) Requests.Add((request.Method.Method, request.RequestUri!.AbsolutePath));
        if (request.Headers.Authorization is null)
        {
            var challenge = Json(401, "{}");
            challenge.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Bearer",
                "authorization=\"https://login.microsoftonline.com/fake-tenant\", resource=\"https://vault.azure.net\""));
            return challenge;
        }
        var name = request.RequestUri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "";
        return await Respond(name, ct).ConfigureAwait(false);
    }
}

public class RealSdkPathTests
{
    private static (SecretsLoadResult Result, CannedVault Vault, ConfigurationManager Cfg) Run(
        Func<string, CancellationToken, Task<HttpResponseMessage>> respond, Action<FischostSecretsOptions>? more = null, params string[] names)
    {
        var vault = new CannedVault { Respond = respond };
        var cfg = new ConfigurationManager();
        var r = cfg.AddFischostSecrets(Fake.Opts(null, o =>
        {
            o.ClientTransport = vault.Transport;
            o.CredentialOverride = new FakeCredential();
            o.MaxRetries = 0;
            foreach (var n in names) o.Add(n, "k:" + n);
            more?.Invoke(o);
        }));
        return (r, vault, cfg);
    }

    [Fact]
    public void Real_source_loads_a_value_with_GET_on_the_secret_url_only()
    {
        var (r, vault, cfg) = Run((n, _) => Task.FromResult(CannedVault.Secret(n, Fake.Value)), null, "App-Key");
        Assert.Equal(SecretStatus.Loaded, r.Outcomes[0].Status);
        Assert.Equal(Fake.Value, cfg["k:App-Key"]);
        AssertOnlySecretGets(vault, "App-Key");
    }

    [Theory]
    [InlineData(404, SecretStatus.NotFound)]
    [InlineData(403, SecretStatus.Denied)]
    [InlineData(401, SecretStatus.SignInFailed)]
    [InlineData(500, SecretStatus.Error)]
    public void Real_source_maps_http_status(int http, SecretStatus expected)
    {
        var (r, vault, _) = Run((_, _) => Task.FromResult(CannedVault.Json(http, "{\"error\":{\"code\":\"X\",\"message\":\"m\"}}")), null, "App-Key");
        Assert.Equal(expected, r.Outcomes[0].Status);
        Assert.Equal(http, r.Outcomes[0].HttpStatus);
        AssertOnlySecretGets(vault, "App-Key");
    }

    [Fact]
    public void Real_source_maps_a_transport_exception_to_Unreachable()
    {
        var (r, _, _) = Run((_, _) => throw new HttpRequestException("network down " + Fake.Value), null, "App-Key");
        Assert.Equal(SecretStatus.Unreachable, r.Outcomes[0].Status);
        Assert.DoesNotContain(Fake.Value, r.Summary() + r.Diagnostics());
    }

    [Fact]
    public void Real_source_is_bounded_by_the_request_timeout_when_the_vault_is_slow()
    {
        var sw = Stopwatch.StartNew();
        var (r, _, _) = Run(async (_, ct) => { await Task.Delay(Timeout.Infinite, ct); return CannedVault.Json(200, "{}"); },
            o => { o.RequestTimeout = TimeSpan.FromMilliseconds(300); o.StartupTimeout = TimeSpan.FromSeconds(5); }, "App-Key");
        sw.Stop();
        Assert.Equal(SecretStatus.Unreachable, r.Outcomes[0].Status);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(4), $"took {sw.Elapsed}");
    }

    [Fact]
    public void Real_source_requests_each_name_and_each_alternate_by_exact_url_never_a_list()
    {
        // second run with alternates
        var vault2 = new CannedVault { Respond = (n, _) => Task.FromResult(n == "Old-Key" ? CannedVault.Secret(n, "v") : CannedVault.Json(404, "{}")) };
        var cfg = new ConfigurationManager();
        var r2 = cfg.AddFischostSecrets(Fake.Opts(null, o =>
        {
            o.ClientTransport = vault2.Transport; o.CredentialOverride = new FakeCredential(); o.MaxRetries = 0;
            o.Add("App-Key", "k", false, "Old-Key");
        }));
        Assert.Equal("Old-Key", r2.Outcomes[0].UsedName);
        AssertOnlySecretGets(vault2, "App-Key", "Old-Key");
    }

    [Fact]
    public void Client_options_carry_the_retry_and_timeout_settings()
    {
        var o = new FischostSecretsOptions { MaxRetries = 4, RequestTimeout = TimeSpan.FromSeconds(7) };
        var c = FischostSecretsExtensions.BuildClientOptions(o);
        Assert.Equal(4, c.Retry.MaxRetries);
        Assert.Equal(TimeSpan.FromSeconds(7), c.Retry.NetworkTimeout);
        Assert.Equal(Azure.Core.RetryMode.Exponential, c.Retry.Mode);
        Assert.Equal(5, FischostSecretsExtensions.BuildClientOptions(new FischostSecretsOptions { MaxRetries = 50 }).Retry.MaxRetries);
    }

    private static void AssertOnlySecretGets(CannedVault vault, params string[] allowedNames)
    {
        Assert.NotEmpty(vault.Requests);
        foreach (var (method, path) in vault.Requests)
        {
            Assert.Equal("GET", method);
            var m = Regex.Match(path, @"^/secrets/([0-9A-Za-z-]+)/?$");
            Assert.True(m.Success, $"unexpected path {path}");
            Assert.Contains(m.Groups[1].Value, allowedNames);
        }
    }
}

[Collection("Legacy")]
public class ReviewFixTests
{
    // 6
    [Fact]
    public async Task OnRefreshProblem_is_called_for_each_failed_refresh_outcome_and_a_throwing_callback_is_swallowed()
    {
        bool fail = false;
        var src = new FakeSource()
            .Custom("A", _ => fail ? throw new Azure.RequestFailedException(500, "x") : Task.FromResult<string?>("a"))
            .Custom("B", _ => Task.FromResult<string?>("b"));
        var seen = new List<SecretOutcome>();
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, src, o => { o.RefreshInterval = TimeSpan.FromHours(1); o.OnRefreshProblem = x => { seen.Add(x); throw new InvalidOperationException("boom"); }; o.Add("A", "ka").Add("B", "kb"); });
        fail = true;
        var p = Assert.Single(((IConfigurationRoot)cfg).Providers.OfType<SecretsConfigurationProvider>());
        await p.RefreshAsync();
        var one = Assert.Single(seen);
        Assert.Equal("A", one.VaultName);
        Assert.Equal(SecretStatus.Error, one.Status);
        Assert.Equal("a", cfg["ka"]);
        Assert.Single(r.RefreshProblems);
    }

    // 8
    [Fact]
    public void Alternate_equal_to_another_entrys_vault_name_is_rejected_in_either_order()
    {
        Assert.Throws<ArgumentException>(() => new FischostSecretsOptions().Add("A", "ka").Add("B", "kb", false, "A"));
        Assert.Throws<ArgumentException>(() => new FischostSecretsOptions().Add("B", "kb", false, "A").Add("A", "ka"));
    }

    [Fact]
    public void Alternate_shared_by_two_entries_or_repeated_or_equal_to_own_name_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => new FischostSecretsOptions().Add("A", "ka", false, "Old").Add("B", "kb", false, "old"));
        Assert.Throws<ArgumentException>(() => new FischostSecretsOptions().Add("A", "ka", false, "Old", "OLD"));
        Assert.Throws<ArgumentException>(() => new FischostSecretsOptions().Add("A", "ka", false, "a"));
    }

    // 10
    [Fact]
    public void Startup_deadline_marks_unfinished_entries_Unreachable_StartupTimeout_even_when_the_source_ignores_cancellation()
    {
        var never = new TaskCompletionSource<string?>().Task;
        var src = new FakeSource();
        var cfg = new ConfigurationManager();
        var sw = Stopwatch.StartNew();
        var r = Fake.Load(cfg, src, o =>
        {
            o.RequestTimeout = TimeSpan.FromMilliseconds(400);
            o.StartupTimeout = TimeSpan.FromMilliseconds(600);
            for (int i = 0; i < 9; i++) { src.Custom($"S-{i}", _ => never); o.Add($"S-{i}", $"k{i}", required: true); }
        });
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"took {sw.Elapsed}");
        Assert.All(r.Outcomes, o => Assert.Equal(SecretStatus.Unreachable, o.Status));
        Assert.Contains(r.Outcomes, o => o.ErrorType == "StartupTimeout");
        Assert.Equal(9, r.Outcomes.Count);
    }

    [Fact]
    public void Startup_timeout_must_be_positive_and_at_least_the_request_timeout()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new FischostSecretsOptions { StartupTimeout = TimeSpan.Zero });
        Assert.Equal(TimeSpan.FromSeconds(30), new FischostSecretsOptions().StartupTimeout);
        Assert.Throws<ArgumentException>(() => Fake.Load(new ConfigurationManager(), new FakeSource(), o => { o.RequestTimeout = TimeSpan.FromSeconds(20); o.StartupTimeout = TimeSpan.FromSeconds(5); }));
    }

    // 11
    [Fact]
    public void No_internal_type_prints_a_value_in_ToString()
    {
        var v = new Dictionary<string, string> { ["k"] = Fake.Value };
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, new FakeSource().Value("A", Fake.Value), o => o.Add("A", "k"));
        var source = new SecretsConfigurationSource(v, r, null, null);
        object[] things =
        [
            new SecretFetch(Fake.Value),
            new LoadBatch(r.Outcomes, v),
            new SecretsLoader.Attempt(SecretStatus.Loaded, Fake.Value, null, null),
            source,
            source.Build(new ConfigurationBuilder()),
            r,
            r.Outcomes[0],
        ];
        foreach (var t in things)
            Assert.DoesNotContain(Fake.Value, t.ToString());
        Assert.DoesNotContain(Fake.Value, ((SecretsConfigurationProvider)source.Build(new ConfigurationBuilder())).ToString());
    }

    // 12
    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(500)]
    public void Refresh_interval_below_one_second_is_rejected_when_options_are_set(int ms)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new FischostSecretsOptions { RefreshInterval = TimeSpan.FromMilliseconds(ms) });
    }

    [Fact]
    public void Refresh_interval_null_or_one_second_is_accepted()
    {
        Assert.Null(new FischostSecretsOptions { RefreshInterval = null }.RefreshInterval);
        Assert.Equal(TimeSpan.FromSeconds(1), new FischostSecretsOptions { RefreshInterval = TimeSpan.FromSeconds(1) }.RefreshInterval);
    }

    // 13
    [Fact]
    public async Task A_throwing_change_handler_does_not_break_refresh()
    {
        var current = "v1";
        var src = new FakeSource().Custom("A", _ => Task.FromResult<string?>(current));
        var cfg = new ConfigurationManager();
        Fake.Load(cfg, src, o => { o.RefreshInterval = TimeSpan.FromHours(1); o.Add("A", "k"); });
        ChangeToken.OnChange(() => ((IConfiguration)cfg).GetReloadToken(), () => throw new InvalidOperationException("handler bug"));
        var p = Assert.Single(((IConfigurationRoot)cfg).Providers.OfType<SecretsConfigurationProvider>());
        current = "v2";
        await p.RefreshAsync();
        Assert.Equal("v2", cfg["k"]);
        current = "v3";
        await p.RefreshAsync();
        Assert.Equal("v3", cfg["k"]);
    }

    [Fact]
    public async Task Building_the_source_twice_gives_one_provider_and_Dispose_stops_the_timer()
    {
        int calls = 0;
        var r = Fake.Load(new ConfigurationManager(), new FakeSource(), o => o.Add("A", "k"));
        var source = new SecretsConfigurationSource(new(), r, _ => { Interlocked.Increment(ref calls); return Task.FromResult(new LoadBatch([], new())); }, TimeSpan.FromSeconds(1));
        var p1 = (SecretsConfigurationProvider)source.Build(new ConfigurationBuilder());
        var p2 = source.Build(new ConfigurationBuilder());
        Assert.Same(p1, p2);
        Assert.True(p1.TimerRunning);

        p1.Dispose();
        Assert.False(p1.TimerRunning);
        Assert.True(p1.IsDisposed);
        await p1.RefreshAsync();
        Assert.Equal(0, calls);
        p1.Dispose(); // second dispose is harmless
    }

    // 4
    private static SecretClient LegacyClient(CannedVault vault) =>
        new(new Uri("https://fake-vault.vault.azure.net/path-that-must-not-leak"), new FakeCredential(),
            new SecretClientOptions { Transport = vault.Transport, Retry = { MaxRetries = 0 } });

    [Theory]
    [InlineData(404)]
    [InlineData(403)]
    [InlineData(500)]
    public void Legacy_Get_message_has_name_and_status_only(int http)
    {
        var vault = new CannedVault { Respond = (_, _) => Task.FromResult(CannedVault.Json(http, "{\"error\":{\"message\":\"https://fake-vault.vault.azure.net/leak\"}}")) };
        Secrets.SetForTests(LegacyClient(vault), "https://fake-vault.vault.azure.net/path-that-must-not-leak");
        try
        {
            var ex = Assert.Throws<InvalidOperationException>(() => Secrets.Get("App-Key"));
            Assert.Contains("App-Key", ex.Message);
            Assert.Contains(http.ToString(), ex.Message);
            Assert.DoesNotContain("fake-vault", ex.Message);
            Assert.DoesNotContain("https://", ex.Message);
            Assert.DoesNotContain("must-not-leak", ex.Message);
            Assert.Null(ex.InnerException);
        }
        finally { Secrets.SetForTests(null, null); }
    }

    [Fact]
    public void Legacy_DumpDiagnostics_prints_the_vault_host_only()
    {
        Secrets.SetForTests(null, "https://fake-vault.vault.azure.net/path-that-must-not-leak?x=1");
        try
        {
            var lines = new List<string>();
            Secrets.DumpDiagnostics(lines.Add);
            var all = string.Join("\n", lines);
            Assert.Contains("fake-vault.vault.azure.net", all);
            Assert.DoesNotContain("https://", all);
            Assert.DoesNotContain("path-that-must-not-leak", all);
        }
        finally { Secrets.SetForTests(null, null); }
    }

    // 1 (refresh path)
    [Fact]
    public async Task Whitespace_value_on_refresh_does_not_replace_the_good_value()
    {
        var current = "v1";
        var src = new FakeSource().Custom("A", _ => Task.FromResult<string?>(current));
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, src, o => { o.RefreshInterval = TimeSpan.FromHours(1); o.Add("A", "k"); });
        current = "   ";
        await Assert.Single(((IConfigurationRoot)cfg).Providers.OfType<SecretsConfigurationProvider>()).RefreshAsync();
        Assert.Equal("v1", cfg["k"]);
        Assert.Equal(SecretStatus.NotFound, Assert.Single(r.RefreshProblems).Status);
    }
}
