#!/usr/bin/env bash
# Builds a throwaway console project that installs the packed Fischost.Secrets and compiles a sample.
# Makes no Azure call: it only builds. Usage: tools/consumer-test.sh [version]   (default: newest in artifacts/packages)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
feed="$root/artifacts/packages"
version="${1:-}"
if [ -z "$version" ]; then
  f="$(ls -1 "$feed"/Fischost.Secrets.*.nupkg 2>/dev/null | grep -v '\.snupkg$' | sort | tail -n1 || true)"
  [ -n "$f" ] || { echo "No package in $feed. Run: dotnet pack -c Release" >&2; exit 1; }
  version="$(basename "$f" .nupkg)"; version="${version#Fischost.Secrets.}"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
cat > nuget.config <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$feed" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="local"><package pattern="Fischost.Secrets" /></packageSource>
    <packageSource key="nuget.org"><package pattern="*" /></packageSource>
  </packageSourceMapping>
</configuration>
EOF
cat > Consumer.csproj <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Fischost.Secrets" Version="$version" />
    <PackageReference Include="Microsoft.Extensions.Logging.Abstractions" Version="10.0.14" />
  </ItemGroup>
</Project>
EOF
cat > Program.cs <<'EOF'
using Fischost.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

// Compile-only sample. Development skips the vault, so even if run it would make no Azure call.
var config = new ConfigurationManager();
var result = config.AddFischostSecrets(o =>
{
    o.App = "Sample";
    o.EnvironmentName = "Development";
    o.Add("Sample-DBConnectionString", "ConnectionStrings:Default", required: true);
    o.Add("Sample-Weather--ApiKey", "Weather:ApiKey", false, "OldWeatherKey");
});
result.Report(NullLogger.Instance);
result.ThrowIfRequiredProblems();
Console.WriteLine(result.Summary());
EOF
dotnet build -c Release --configfile nuget.config -v quiet 2>&1 | tail -5
echo "consumer-test: OK (Fischost.Secrets $version installed and compiled)"
