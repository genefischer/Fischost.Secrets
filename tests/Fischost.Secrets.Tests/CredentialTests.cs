using Microsoft.Extensions.Configuration;

namespace Fischost.Secrets.Tests;

public class CredentialTests
{
    private static CredentialPlan Choose(Dictionary<string, string?> vars, string env = "Production", bool allowVault = false, bool allowDefault = false) =>
        CredentialSelector.Choose(vars, env, new FischostSecretsOptions { AllowVaultInDevelopment = allowVault, AllowDefaultAzureCredentialInDevelopment = allowDefault });

    [Fact]
    public void Certificate_when_path_tenant_and_client_are_set()
    {
        var p = Choose(new() { ["AZURE_CLIENT_CERTIFICATE_PATH"] = "/x/c.pem", ["AZURE_TENANT_ID"] = "t", ["AZURE_CLIENT_ID"] = "c" });
        Assert.Equal(CredentialMode.Certificate, p.Mode);
        Assert.True(p.IsOk);
    }

    [Fact]
    public void Certificate_wins_over_client_secret()
    {
        var v = Fake.ClientSecretVars();
        v["AZURE_CLIENT_CERTIFICATE_PATH"] = "/x/c.pem";
        Assert.Equal(CredentialMode.Certificate, Choose(v).Mode);
    }

    [Theory]
    [InlineData("AZURE_TENANT_ID")]
    [InlineData("AZURE_CLIENT_ID")]
    public void Certificate_path_without_tenant_or_client_is_a_hard_failure_naming_the_variable(string missing)
    {
        var v = new Dictionary<string, string?> { ["AZURE_CLIENT_CERTIFICATE_PATH"] = "/x/c.pem", ["AZURE_TENANT_ID"] = "t", ["AZURE_CLIENT_ID"] = "c" };
        v.Remove(missing);
        var p = Choose(v);
        Assert.False(p.IsOk);
        Assert.Contains(missing, p.Problem);
    }

    [Fact]
    public void Client_secret_when_all_three_are_set()
    {
        Assert.Equal(CredentialMode.ClientSecret, Choose(Fake.ClientSecretVars()).Mode);
    }

    [Theory]
    [InlineData("AZURE_TENANT_ID")]
    [InlineData("AZURE_CLIENT_ID")]
    [InlineData("AZURE_CLIENT_SECRET")]
    public void Partial_client_secret_set_is_a_hard_failure_naming_only_the_missing_names(string missing)
    {
        var v = Fake.ClientSecretVars();
        v.Remove(missing);
        var p = Choose(v);
        Assert.False(p.IsOk);
        Assert.Equal(CredentialMode.None, p.Mode);
        Assert.Contains(missing, p.Problem);
        foreach (var present in Fake.ClientSecretVars().Keys.Where(k => k != missing))
            Assert.DoesNotContain(present + ",", p.Problem!.Split("missing:")[1]);
        Assert.DoesNotContain("fake-client-pw", p.Problem);
        Assert.DoesNotContain("fake-tenant", p.Problem);
    }

    [Fact]
    public void Blank_values_count_as_unset()
    {
        var v = Fake.ClientSecretVars();
        v["AZURE_CLIENT_SECRET"] = "   ";
        Assert.Contains("AZURE_CLIENT_SECRET", Choose(v).Problem);
    }

    [Fact]
    public void Client_id_alone_is_user_assigned_managed_identity()
    {
        Assert.Equal(CredentialMode.ManagedIdentity, Choose(new() { ["AZURE_CLIENT_ID"] = "c" }).Mode);
    }

    [Fact]
    public void System_assigned_identity_needs_the_explicit_flag()
    {
        Assert.False(Choose(new()).IsOk);
        Assert.Equal(CredentialMode.ManagedIdentity, Choose(new() { ["FISCHOST_SECRETS_MANAGED_IDENTITY"] = "1" }).Mode);
        Assert.False(Choose(new() { ["FISCHOST_SECRETS_MANAGED_IDENTITY"] = "0" }).IsOk);
    }

    [Fact]
    public void No_variables_at_all_in_Production_fails_with_guidance_and_no_DefaultAzure()
    {
        var p = Choose(new(), "Production", allowVault: true, allowDefault: true);
        Assert.False(p.IsOk);
        Assert.NotEqual(CredentialMode.DefaultAzure, p.Mode);
        Assert.Contains("AZURE_TENANT_ID", p.Problem);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("production")]
    [InlineData("")]
    public void DefaultAzure_is_never_chosen_outside_Development_even_when_asked(string env)
    {
        var p = Choose(new(), env, allowVault: true, allowDefault: true);
        Assert.NotEqual(CredentialMode.DefaultAzure, p.Mode);
        Assert.False(p.IsOk);
    }

    [Fact]
    public void DefaultAzure_only_in_Development_with_both_flags()
    {
        Assert.Equal(CredentialMode.DefaultAzure, Choose(new(), "development", true, true).Mode);
        Assert.False(Choose(new(), "Development", true, false).IsOk);
        Assert.False(Choose(new(), "Development", false, true).IsOk);
    }

    [Fact]
    public void Partial_variables_in_Development_still_fail_instead_of_falling_back()
    {
        var p = Choose(new() { ["AZURE_CLIENT_ID"] = "c", ["AZURE_TENANT_ID"] = "t" }, "Development", true, true);
        Assert.False(p.IsOk);
        Assert.Contains("AZURE_CLIENT_SECRET", p.Problem);
    }

    [Fact]
    public void Partial_variables_make_every_entry_SignInFailed_without_asking_the_vault_and_throw_in_Production()
    {
        var src = new FakeSource().Value("A", "a").Value("B", "b");
        var vars = Fake.ClientSecretVars(); vars.Remove("AZURE_TENANT_ID");
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, src, o => o.Add("A", "a", required: true).Add("B", "b"), vars);
        Assert.Empty(src.Asked);
        Assert.All(r.Outcomes, o => Assert.Equal(SecretStatus.SignInFailed, o.Status));
        Assert.Contains("AZURE_TENANT_ID", r.CredentialProblem);
        var ex = Assert.Throws<FischostSecretsException>(r.ThrowIfRequiredProblems);
        Assert.Contains("AZURE_TENANT_ID", ex.Message);
        Assert.Contains("A (SignInFailed)", ex.Message);
    }

    [Fact]
    public void Credentials_can_be_created_offline_from_fake_values()
    {
        var vars = Fake.ClientSecretVars();
        Assert.IsType<Azure.Identity.ClientSecretCredential>(CredentialSelector.Create(CredentialMode.ClientSecret, Fake.Reader(vars)));
        Assert.IsType<Azure.Identity.ManagedIdentityCredential>(CredentialSelector.Create(CredentialMode.ManagedIdentity, Fake.Reader(vars)));
        Assert.IsType<Azure.Identity.ManagedIdentityCredential>(CredentialSelector.Create(CredentialMode.ManagedIdentity, _ => null));
        Assert.Throws<InvalidOperationException>(() => CredentialSelector.Create(CredentialMode.None, Fake.Reader(vars)));
    }
}
