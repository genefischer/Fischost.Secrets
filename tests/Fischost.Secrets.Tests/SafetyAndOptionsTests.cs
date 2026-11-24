using System.Net.Http;
using Azure;
using Microsoft.Extensions.Configuration;

namespace Fischost.Secrets.Tests;

public class SafetyAndOptionsTests
{
    [Fact]
    public void No_secret_value_appears_in_any_output()
    {
        // Values come back for some entries; failures carry the value in their exception messages.
        var src = new FakeSource()
            .Value("A-Loaded", Fake.Value)
            .Fail("B-Denied", new RequestFailedException(403, "denied " + Fake.Value))
            .Fail("C-Boom", new InvalidOperationException("boom " + Fake.Value))
            .Fail("D-Net", new HttpRequestException("net " + Fake.Value, new Exception(Fake.Value)));
        var cfg = new ConfigurationManager();
        var vars = Fake.ClientSecretVars();
        var r = Fake.Load(cfg, src, o => o.Add("A-Loaded", "a", true).Add("B-Denied", "b", true).Add("C-Boom", "c", true).Add("D-Net", "d", true).Add("E-Missing", "e", true), vars);
        var log = new TestLogger();
        r.Report(log);
        var ex = Assert.Throws<FischostSecretsException>(r.ThrowIfRequiredProblems);

        Assert.Equal(Fake.Value, cfg["a"]); // the value is in configuration and nowhere else
        var everything = string.Join("\n", r.Summary(), r.Diagnostics(), r.ToString(), log.All, ex.Message, ex.ToString(),
            string.Join("\n", r.Outcomes.Select(o => o.ToString())), string.Join(",", r.RequiredMissing));
        Assert.DoesNotContain(Fake.Value, everything);
        Assert.DoesNotContain("fake-client-pw", everything);
        Assert.DoesNotContain("fake-tenant", everything);
        Assert.DoesNotContain("fake-vault.vault.azure.net/", everything); // never the full URL
    }

    [Fact]
    public void Outcome_has_no_member_that_could_carry_a_value_or_message()
    {
        var names = typeof(SecretOutcome).GetProperties().Select(p => p.Name).ToHashSet();
        Assert.DoesNotContain("Value", names);
        Assert.DoesNotContain("Message", names);
        Assert.DoesNotContain("Exception", names);
        Assert.Equal(typeof(string), typeof(SecretOutcome).GetProperty("ErrorType")!.PropertyType);
    }

    [Fact]
    public void SecretFetch_ToString_hides_the_value()
    {
        Assert.DoesNotContain(Fake.Value, new SecretFetch(Fake.Value).ToString());
    }

    [Fact]
    public void Duplicate_vault_names_are_rejected_case_insensitively()
    {
        var o = new FischostSecretsOptions().Add("A-One", "k1");
        Assert.Throws<ArgumentException>(() => o.Add("a-one", "k2"));
    }

    [Fact]
    public void Duplicate_config_keys_are_rejected_case_insensitively()
    {
        var o = new FischostSecretsOptions().Add("A-One", "Db:Conn");
        Assert.Throws<ArgumentException>(() => o.Add("A-Two", "db:conn"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("has space")]
    [InlineData("under_score")]
    [InlineData("dot.name")]
    [InlineData("a/b")]
    [InlineData("a?api-version=1")]
    [InlineData("a%2Fb")]
    [InlineData("..")]
    [InlineData("Good-Name\n")]
    [InlineData("\nGood-Name")]
    [InlineData("Good-Name\r\n")]
    public void Bad_vault_names_are_rejected(string name)
    {
        Assert.Throws<ArgumentException>(() => new FischostSecretsOptions().Add(name, "k"));
        Assert.Throws<ArgumentException>(() => new FischostSecretsOptions().Add("Good-Name", "k", false, name));
    }

    [Fact]
    public void Name_length_limit_is_127()
    {
        new FischostSecretsOptions().Add(new string('a', 127), "k");
        Assert.Throws<ArgumentException>(() => new FischostSecretsOptions().Add(new string('a', 128), "k"));
    }

    [Fact]
    public void Blank_config_key_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => new FischostSecretsOptions().Add("A", " "));
    }

    [Fact]
    public void Add_is_fluent_and_keeps_alternates_in_order()
    {
        var o = new FischostSecretsOptions().Add("New-Name", "k", true, "Old-1", "Old-2").Add("Other", "j");
        Assert.Equal(2, o.Entries.Count);
        Assert.Equal(["Old-1", "Old-2"], o.Entries[0].Alternates);
        Assert.True(o.Entries[0].Required);
    }

    [Fact]
    public void MaxRetries_is_capped_at_five_and_floored_at_zero()
    {
        var o = new FischostSecretsOptions { MaxRetries = 99 };
        Assert.Equal(5, o.MaxRetries);
        o.MaxRetries = -3;
        Assert.Equal(0, o.MaxRetries);
        Assert.Equal(2, new FischostSecretsOptions().MaxRetries);
        Assert.Equal(TimeSpan.FromSeconds(10), new FischostSecretsOptions().RequestTimeout);
        Assert.Throws<ArgumentOutOfRangeException>(() => new FischostSecretsOptions { RequestTimeout = TimeSpan.Zero });
    }
}
