#pragma warning disable CS0618 // the legacy class is obsolete on purpose

namespace Fischost.Secrets.Tests;

[Collection("Legacy")]
public class LegacyTests
{
    [Fact]
    public void TryGet_returns_false_when_not_initialised()
    {
        var ok = Secrets.TryGet("Anything", out var value);
        Assert.False(ok);
        Assert.Null(value);
    }

    [Fact]
    public void Get_throws_when_not_initialised()
    {
        Assert.Throws<InvalidOperationException>(() => Secrets.Get("Anything"));
    }

    [Fact]
    public void DumpDiagnostics_works_when_not_initialised_and_prints_no_values()
    {
        var lines = new List<string>();
        Secrets.DumpDiagnostics(lines.Add);
        Assert.Contains(lines, l => l.Contains("(not set)"));
        Assert.Contains(lines, l => l.Contains("Uninitialized"));
    }

    [Fact]
    public void Legacy_class_is_marked_obsolete()
    {
        Assert.NotNull(Attribute.GetCustomAttribute(typeof(Secrets), typeof(ObsoleteAttribute)));
    }
}
