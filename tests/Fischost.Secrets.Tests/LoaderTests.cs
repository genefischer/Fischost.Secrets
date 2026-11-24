using System.Net.Http;
using Azure;
using Azure.Identity;
using Microsoft.Extensions.Configuration;

namespace Fischost.Secrets.Tests;

public class LoaderTests
{
    private static SecretOutcome One(FakeSource src, Action<FischostSecretsOptions>? more = null, bool required = false, params string[] alts)
    {
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, src, o => { o.Add("App-Key", "Key", required, alts); more?.Invoke(o); });
        return Assert.Single(r.Outcomes);
    }

    [Fact]
    public void Loaded_value_reaches_configuration_under_the_config_key()
    {
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, new FakeSource().Value("App-Db", Fake.Value), o => o.Add("App-Db", "ConnectionStrings:Db"));
        Assert.Equal(Fake.Value, cfg["ConnectionStrings:Db"]);
        Assert.Equal(SecretStatus.Loaded, r.Outcomes[0].Status);
        Assert.Equal("App-Db", r.Outcomes[0].UsedName);
    }

    [Theory]
    [InlineData(404, SecretStatus.NotFound)]
    [InlineData(403, SecretStatus.Denied)]
    [InlineData(401, SecretStatus.SignInFailed)]
    [InlineData(500, SecretStatus.Error)]
    [InlineData(429, SecretStatus.Error)]
    public void Http_status_maps_to_outcome_status(int http, SecretStatus expected)
    {
        var o = One(new FakeSource().Http("App-Key", http));
        Assert.Equal(expected, o.Status);
        Assert.Equal(http, o.HttpStatus);
        Assert.Null(o.UsedName);
    }

    [Fact]
    public void Transport_failure_is_Unreachable()
    {
        Assert.Equal(SecretStatus.Unreachable, One(new FakeSource().Fail("App-Key", new HttpRequestException("boom"))).Status);
        Assert.Equal(SecretStatus.Unreachable, One(new FakeSource().Fail("App-Key", new RequestFailedException(0, "transport"))).Status);
        Assert.Equal(SecretStatus.Unreachable, One(new FakeSource().Fail("App-Key", new TimeoutException())).Status);
    }

    [Fact]
    public void Credential_failure_is_SignInFailed()
    {
        Assert.Equal(SecretStatus.SignInFailed, One(new FakeSource().Fail("App-Key", new AuthenticationFailedException("bad"))).Status);
        Assert.Equal(SecretStatus.SignInFailed, One(new FakeSource().Fail("App-Key", new CredentialUnavailableException("none"))).Status);
    }

    [Fact]
    public void Unexpected_exception_is_Error_with_type_name_only()
    {
        var o = One(new FakeSource().Fail("App-Key", new InvalidOperationException("secret FAKE-VALUE-12345 inside")));
        Assert.Equal(SecretStatus.Error, o.Status);
        Assert.Equal("InvalidOperationException", o.ErrorType);
    }

    [Fact]
    public void Request_timeout_is_Unreachable()
    {
        var o = One(new FakeSource().Hang("App-Key"), x => x.RequestTimeout = TimeSpan.FromMilliseconds(50));
        Assert.Equal(SecretStatus.Unreachable, o.Status);
        Assert.Equal("Timeout", o.ErrorType);
    }

    [Fact]
    public void Empty_value_counts_as_NotFound()
    {
        Assert.Equal(SecretStatus.NotFound, One(new FakeSource().Value("App-Key", "")).Status);
        Assert.Equal(SecretStatus.NotFound, One(new FakeSource().Value("App-Key", null)).Status);
    }

    [Fact]
    public void Alternates_are_tried_in_order_after_NotFound()
    {
        var src = new FakeSource().Value("Old-One", Fake.Value).Value("Older-One", "other");
        var o = One(src, null, false, "Old-One", "Older-One");
        Assert.Equal(SecretStatus.Loaded, o.Status);
        Assert.Equal("App-Key", o.VaultName);
        Assert.Equal("Old-One", o.UsedName);
        Assert.Equal(["App-Key", "Old-One"], src.Asked);
    }

    [Fact]
    public void Alternates_are_not_tried_when_the_first_name_is_denied()
    {
        var src = new FakeSource().Http("App-Key", 403).Value("Old-One", Fake.Value);
        var o = One(src, null, false, "Old-One");
        Assert.Equal(SecretStatus.Denied, o.Status);
        Assert.Equal(["App-Key"], src.Asked);
    }

    [Fact]
    public void Real_problem_on_an_alternate_outranks_NotFound()
    {
        var src = new FakeSource().Http("Old-One", 403);
        Assert.Equal(SecretStatus.Denied, One(src, null, false, "Old-One").Status);
    }

    [Fact]
    public void All_names_missing_is_NotFound()
    {
        var src = new FakeSource();
        Assert.Equal(SecretStatus.NotFound, One(src, null, false, "Old-One").Status);
        Assert.Equal(["App-Key", "Old-One"], src.Asked);
    }

    [Fact]
    public void One_failure_does_not_abort_the_others()
    {
        var cfg = new ConfigurationManager();
        var src = new FakeSource().Http("A", 500).Value("B", "b-val").Http("C", 403).Value("D", "d-val");
        var r = Fake.Load(cfg, src, o => o.Add("A", "a").Add("B", "b").Add("C", "c").Add("D", "d"));
        Assert.Equal("b-val", cfg["b"]);
        Assert.Equal("d-val", cfg["d"]);
        Assert.Null(cfg["a"]);
        Assert.Equal(2, r.Outcomes.Count(x => x.Status == SecretStatus.Loaded));
    }

    [Fact]
    public void Parallelism_is_capped_at_eight_but_used()
    {
        var src = new FakeSource { Delay = TimeSpan.FromMilliseconds(40) };
        var cfg = new ConfigurationManager();
        Fake.Load(cfg, src, o => { for (int i = 0; i < 30; i++) { src.Value($"S-{i}", "v"); o.Add($"S-{i}", $"k{i}"); } });
        Assert.Equal(30, src.Asked.Count);
        Assert.InRange(src.MaxConcurrent, 2, SecretsLoader.MaxParallel);
    }

    [Fact]
    public void Source_interface_has_one_method_and_no_listing()
    {
        var methods = typeof(ISecretSource).GetMethods();
        var m = Assert.Single(methods);
        Assert.Equal("GetAsync", m.Name);
        Assert.DoesNotContain(typeof(KeyVaultSecretSource).GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.DeclaredOnly), x => x.Name != "GetAsync");
        var all = typeof(KeyVaultSecretSource).Assembly.GetTypes()
            .SelectMany(t => t.GetMembers(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.DeclaredOnly))
            .Select(x => x.Name);
        Assert.DoesNotContain(all, n => n.Contains("PropertiesOfSecrets", StringComparison.Ordinal));
    }

    [Fact]
    public void Vault_overrides_an_earlier_in_memory_source()
    {
        var cfg = new ConfigurationManager();
        cfg.AddInMemoryCollection(new Dictionary<string, string?> { ["Stripe:Key"] = "from-appsettings", ["Other"] = "kept" });
        Fake.Load(cfg, new FakeSource().Value("App-Stripe", Fake.Value), o => o.Add("App-Stripe", "Stripe:Key"));
        Assert.Equal(Fake.Value, cfg["Stripe:Key"]);
        Assert.Equal("kept", cfg["Other"]);
    }

    [Fact]
    public void Missing_secret_leaves_the_earlier_value_in_place()
    {
        var cfg = new ConfigurationManager();
        cfg.AddInMemoryCollection(new Dictionary<string, string?> { ["Stripe:Key"] = "from-appsettings" });
        Fake.Load(cfg, new FakeSource(), o => o.Add("App-Stripe", "Stripe:Key"));
        Assert.Equal("from-appsettings", cfg["Stripe:Key"]);
    }
}
