using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Fischost.Secrets.Tests;

public class StartupTests
{
    [Fact]
    public void MissingRequiredSecret_StopsStartup_InProduction()
    {
        var cfg = new ConfigurationManager();
        var src = new FakeSource().Value("App-Optional", Fake.Value); // App-Required is NotFound
        var result = cfg.AddFischostSecrets(Fake.Opts(src, o => o.Add("App-Required", "Db:Conn", required: true).Add("App-Optional", "Opt:Key")));

        result.Report(new TestLogger());
        var ex = Assert.Throws<FischostSecretsException>(result.ThrowIfRequiredProblems);

        Assert.Contains("App-Required", ex.Message);
        Assert.Contains("NotFound", ex.Message);
        Assert.DoesNotContain("App-Optional", ex.Message);
        Assert.DoesNotContain(Fake.Value, ex.Message);
    }

    [Fact]
    public void AddFischostSecrets_itself_never_throws_for_missing_secrets()
    {
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, new FakeSource(), o => o.Add("App-Required", "k", required: true));
        Assert.Equal(["App-Required"], r.RequiredMissing);
    }

    [Fact]
    public void Development_is_the_only_environment_that_never_throws()
    {
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, new FakeSource(), o => { o.EnvironmentName = "Development"; o.AllowVaultInDevelopment = true; o.Add("App-Required", "k", required: true); });
        r.ThrowIfRequiredProblems(); // no exception
        Assert.Equal(["App-Required"], r.RequiredMissing);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("production")]
    [InlineData("PRODUCTION")]
    [InlineData("Staging")]
    [InlineData("Testing")]
    [InlineData("Prod")]
    [InlineData("Live")]
    [InlineData("UAT")]
    [InlineData("SomethingUnknown")]
    public void Every_environment_except_Development_throws_on_a_missing_required_secret(string env)
    {
        var r = Fake.Load(new ConfigurationManager(), new FakeSource(), o => { o.EnvironmentName = env; o.Add("A", "k", required: true); });
        Assert.Throws<FischostSecretsException>(r.ThrowIfRequiredProblems);
    }

    private static Func<string, string?> Env(string? aspnet, string? dotnet) => n => n switch
    {
        "ASPNETCORE_ENVIRONMENT" => aspnet,
        "DOTNET_ENVIRONMENT" => dotnet,
        _ => null,
    };

    [Theory]
    [InlineData(null, null, "Production")]
    [InlineData("Staging", null, "Staging")]
    [InlineData(null, "Staging", "Staging")]
    [InlineData("Staging", "Development", "Staging")]
    [InlineData("Development", "Staging", "Staging")]
    [InlineData("Development", "Production", "Production")]
    [InlineData("Development", "Development", "Development")]
    [InlineData("development", null, "development")]
    [InlineData(null, "Development", "Development")]
    [InlineData("  ", "Development", "Development")]
    public void Environment_is_Development_only_when_every_set_variable_says_so(string? aspnet, string? dotnet, string expected)
    {
        var o = new FischostSecretsOptions { EnvironmentReader = Env(aspnet, dotnet) };
        Assert.Equal(expected, o.EnvironmentName);
    }

    [Fact]
    public void Aspnet_variable_wins_over_dotnet_variable_when_both_name_non_Development_environments()
    {
        var o = new FischostSecretsOptions { EnvironmentReader = Env("Staging", "Production") };
        Assert.Equal("Staging", o.EnvironmentName);
    }

    [Fact]
    public void Disagreeing_variables_use_the_vault_and_enforce_the_throw_rule()
    {
        var src = new FakeSource();
        var r = Fake.Load(new ConfigurationManager(), src, o =>
        {
            o.EnvironmentName = null!; // fall back to the variables
            o.EnvironmentReader = n => n switch
            {
                "ASPNETCORE_ENVIRONMENT" => "Development",
                "DOTNET_ENVIRONMENT" => "Production",
                "AZURE_TENANT_ID" => "t", "AZURE_CLIENT_ID" => "c", "AZURE_CLIENT_SECRET" => "s",
                _ => null,
            };
            o.Add("A", "k", required: true);
        });
        Assert.False(r.Skipped);
        Assert.Equal(["A"], src.Asked);
        Assert.Throws<FischostSecretsException>(r.ThrowIfRequiredProblems);
    }

    [Fact]
    public void Optional_missing_never_throws_in_Production()
    {
        var r = Fake.Load(new ConfigurationManager(), new FakeSource(), o => o.Add("A", "k"));
        r.ThrowIfRequiredProblems();
        Assert.Empty(r.RequiredMissing);
    }

    [Fact]
    public void All_required_present_does_not_throw()
    {
        var r = Fake.Load(new ConfigurationManager(), new FakeSource().Value("A", "v"), o => o.Add("A", "k", required: true));
        r.ThrowIfRequiredProblems();
    }

    [Fact]
    public void Required_secret_that_is_denied_throws_naming_the_status()
    {
        var r = Fake.Load(new ConfigurationManager(), new FakeSource().Http("A", 403), o => o.Add("A", "k", required: true));
        var ex = Assert.Throws<FischostSecretsException>(r.ThrowIfRequiredProblems);
        Assert.Contains("A (Denied)", ex.Message);
    }

    [Fact]
    public void Development_skips_the_vault_creates_no_credential_and_asks_nothing()
    {
        var src = new FakeSource().Value("A", "v");
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, src, o => { o.EnvironmentName = "development"; o.Add("A", "k", required: true); }, vars: new Dictionary<string, string?>());
        Assert.True(r.Skipped);
        Assert.Equal("development", r.SkipReason);
        Assert.Equal(CredentialMode.None, r.CredentialMode);
        Assert.Empty(src.Asked);
        Assert.Null(cfg["k"]);
        r.ThrowIfRequiredProblems();
    }

    [Fact]
    public void AllowVaultInDevelopment_uses_the_vault()
    {
        var src = new FakeSource().Value("A", "v");
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, src, o => { o.EnvironmentName = "Development"; o.AllowVaultInDevelopment = true; o.Add("A", "k"); });
        Assert.False(r.Skipped);
        Assert.Equal("v", cfg["k"]);
    }

    [Fact]
    public void No_vault_url_in_Production_with_required_entries_throws()
    {
        var src = new FakeSource();
        var r = Fake.Load(new ConfigurationManager(), src, o => { o.VaultUrl = ""; o.Add("A", "k", required: true).Add("B", "j"); });
        Assert.True(r.Skipped);
        Assert.Equal("no vault url", r.SkipReason);
        Assert.Empty(src.Asked);
        var ex = Assert.Throws<FischostSecretsException>(r.ThrowIfRequiredProblems);
        Assert.Contains("A (no vault url)", ex.Message);
        Assert.DoesNotContain("B", ex.Message.Replace("TestApp", ""));
    }

    [Fact]
    public void No_vault_url_in_Production_without_required_entries_does_not_throw()
    {
        var r = Fake.Load(new ConfigurationManager(), null, o => { o.VaultUrl = ""; o.Add("A", "k"); });
        Assert.True(r.Skipped);
        r.ThrowIfRequiredProblems();
    }

    [Fact]
    public void No_vault_url_is_skipped_and_throws_only_outside_Development()
    {
        var staging = Fake.Load(new ConfigurationManager(), null, o => { o.VaultUrl = null; o.EnvironmentReader = _ => null; o.EnvironmentName = "Staging"; o.Add("A", "k", required: true); });
        Assert.Equal("no vault url", staging.SkipReason);
        Assert.Throws<FischostSecretsException>(staging.ThrowIfRequiredProblems);

        var dev = Fake.Load(new ConfigurationManager(), null, o => { o.VaultUrl = null; o.EnvironmentReader = _ => null; o.EnvironmentName = "Development"; o.AllowVaultInDevelopment = true; o.Add("A", "k", required: true); });
        Assert.Equal("no vault url", dev.SkipReason);
        dev.ThrowIfRequiredProblems();
    }

    [Fact]
    public void Vault_url_defaults_to_KEYVAULT_URL()
    {
        var vars = Fake.ClientSecretVars();
        vars["KEYVAULT_URL"] = Fake.VaultUrl;
        var o = new FischostSecretsOptions { EnvironmentReader = Fake.Reader(vars) };
        Assert.Equal(Fake.VaultUrl, o.VaultUrl);
    }

    [Fact]
    public void Invalid_vault_url_is_reported_without_echoing_it()
    {
        var r = Fake.Load(new ConfigurationManager(), new FakeSource(), o => { o.VaultUrl = "http://secret-host-FAKE/"; o.Add("A", "k", required: true); });
        Assert.Equal(SecretStatus.Error, r.Outcomes[0].Status);
        Assert.DoesNotContain("secret-host-FAKE", r.Summary() + r.Diagnostics() + r.CredentialProblem);
        Assert.Throws<FischostSecretsException>(r.ThrowIfRequiredProblems);
    }

    [Fact]
    public void App_is_required()
    {
        Assert.Throws<ArgumentException>(() => new ConfigurationManager().AddFischostSecrets(o => o.App = ""));
    }

    [Fact]
    public void Summary_matches_the_documented_shape()
    {
        var src = new FakeSource();
        for (int i = 1; i <= 11; i++) src.Value($"Upkeepify-S{i}", "v");
        var r = Fake.Load(new ConfigurationManager(), src, o =>
        {
            o.App = "Upkeepify";
            for (int i = 1; i <= 11; i++) o.Add($"Upkeepify-S{i}", $"k{i}", required: i == 1);
            o.Add("Weather--ApiKey", "Weather:Key");
        });
        Assert.Equal("Upkeepify secrets: 11 loaded, 1 optional not found (Weather--ApiKey), 0 required problems", r.Summary());
    }

    [Fact]
    public void Summary_lists_required_problems_with_status()
    {
        var r = Fake.Load(new ConfigurationManager(), new FakeSource().Http("B", 403), o => o.Add("A", "a", true).Add("B", "b", true));
        Assert.Equal("TestApp secrets: 0 loaded, 2 required problems (A: NotFound, B: Denied)", r.Summary());
    }

    [Fact]
    public void Report_logs_Error_for_required_problems_Warning_for_optional_and_Information_when_clean()
    {
        var bad = new TestLogger();
        Fake.Load(new ConfigurationManager(), new FakeSource(), o => o.Add("A", "a", true)).Report(bad);
        Assert.Equal(LogLevel.Error, bad.Lines[0].Level);

        var warn = new TestLogger();
        Fake.Load(new ConfigurationManager(), new FakeSource(), o => o.Add("A", "a")).Report(warn);
        Assert.Equal(LogLevel.Warning, warn.Lines[0].Level);

        var ok = new TestLogger();
        Fake.Load(new ConfigurationManager(), new FakeSource().Value("A", "v"), o => o.Add("A", "a")).Report(ok);
        Assert.Equal(LogLevel.Information, Assert.Single(ok.Lines).Level);
    }

    [Fact]
    public void Diagnostics_shows_host_mode_and_variable_names_as_Y_or_N()
    {
        var r = Fake.Load(new ConfigurationManager(), new FakeSource().Value("A", "v"), o => o.Add("A", "a"));
        var d = r.Diagnostics();
        Assert.Contains(Fake.Host, d);
        Assert.Contains("Credential mode: ClientSecret", d);
        Assert.Contains("AZURE_CLIENT_SECRET=Y", d);
        Assert.Contains("AZURE_CLIENT_CERTIFICATE_PATH=N", d);
        Assert.Contains("Environment: Production", d);
        Assert.DoesNotContain("https://", d);
    }

    [Fact]
    public void Vault_host_is_the_host_only()
    {
        var r = Fake.Load(new ConfigurationManager(), new FakeSource(), o => { o.VaultUrl = "https://fake-vault.vault.azure.net:443/some/path?x=1"; o.Add("A", "a"); });
        Assert.Equal(Fake.Host, r.VaultHost);
    }
}
