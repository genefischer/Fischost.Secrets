using Azure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;

namespace Fischost.Secrets.Tests;

public class RefreshTests
{
    private static SecretsConfigurationProvider Provider(ConfigurationManager cfg) =>
        Assert.Single(((IConfigurationRoot)cfg).Providers.OfType<SecretsConfigurationProvider>());

    [Fact]
    public async Task Refresh_picks_up_a_rotated_value_and_signals_a_reload()
    {
        var current = "v1";
        var src = new FakeSource().Custom("A", _ => Task.FromResult<string?>(current));
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, src, o => { o.RefreshInterval = TimeSpan.FromHours(1); o.Add("A", "k"); });
        Assert.Equal("v1", cfg["k"]);

        int reloads = 0;
        ChangeToken.OnChange(() => ((IConfiguration)cfg).GetReloadToken(), () => Interlocked.Increment(ref reloads));
        current = "v2";
        await Provider(cfg).RefreshAsync();

        Assert.Equal("v2", cfg["k"]);
        Assert.True(reloads >= 1);
        Assert.Empty(r.RefreshProblems);
        Assert.NotNull(r.LastRefreshUtc);
    }

    [Fact]
    public async Task Failed_refresh_keeps_the_last_good_value_and_records_a_problem()
    {
        bool fail = false;
        var src = new FakeSource().Custom("A", _ => fail ? throw new RequestFailedException(500, "x") : Task.FromResult<string?>(Fake.Value));
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, src, o => { o.RefreshInterval = TimeSpan.FromHours(1); o.Add("A", "k"); });

        fail = true;
        await Provider(cfg).RefreshAsync();

        Assert.Equal(Fake.Value, cfg["k"]);
        var p = Assert.Single(r.RefreshProblems);
        Assert.Equal(SecretStatus.Error, p.Status);
        Assert.DoesNotContain(Fake.Value, p.ToString());
    }

    [Fact]
    public async Task Refresh_that_finds_the_secret_gone_does_not_blank_it()
    {
        bool gone = false;
        var src = new FakeSource().Custom("A", _ => Task.FromResult<string?>(gone ? "" : "v1"));
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, src, o => { o.RefreshInterval = TimeSpan.FromHours(1); o.Add("A", "k"); });
        gone = true;
        await Provider(cfg).RefreshAsync();
        Assert.Equal("v1", cfg["k"]);
        Assert.Equal(SecretStatus.NotFound, Assert.Single(r.RefreshProblems).Status);
    }

    [Fact]
    public async Task Refresh_can_load_a_secret_that_failed_at_startup()
    {
        bool up = false;
        var src = new FakeSource().Custom("A", _ => up ? Task.FromResult<string?>("late") : throw new HttpRequestExceptionLike());
        var cfg = new ConfigurationManager();
        var r = Fake.Load(cfg, src, o => { o.RefreshInterval = TimeSpan.FromHours(1); o.Add("A", "k", true); });
        Assert.Null(cfg["k"]);
        up = true;
        await Provider(cfg).RefreshAsync();
        Assert.Equal("late", cfg["k"]);
    }

    private sealed class HttpRequestExceptionLike : System.Net.Http.HttpRequestException { }

    [Fact]
    public async Task Without_a_refresh_interval_the_source_is_a_plain_snapshot()
    {
        var current = "v1";
        var src = new FakeSource().Custom("A", _ => Task.FromResult<string?>(current));
        var cfg = new ConfigurationManager();
        Fake.Load(cfg, src, o => o.Add("A", "k"));
        Assert.False(Provider(cfg).TimerRunning);
        current = "v2";
        await Provider(cfg).RefreshAsync(); // nothing to re-read with
        Assert.Equal("v1", cfg["k"]);
        Assert.Single(src.Asked);
    }

    [Fact]
    public async Task The_timer_refreshes_on_its_own_interval()
    {
        var current = "v1";
        var src = new FakeSource().Custom("A", _ => Task.FromResult<string?>(current));
        var cfg = new ConfigurationManager();
        Fake.Load(cfg, src, o => { o.RefreshInterval = TimeSpan.FromSeconds(1); o.Add("A", "k"); });
        var seen = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        ChangeToken.OnChange(() => ((IConfiguration)cfg).GetReloadToken(), () => seen.TrySetResult());
        current = "v2";
        var done = await Task.WhenAny(seen.Task, Task.Delay(TimeSpan.FromSeconds(30)));
        Assert.Same(seen.Task, done);
        Assert.Equal("v2", cfg["k"]);
        ((IDisposable)cfg).Dispose();
    }
}
