using Azure.Core;
using Azure.Identity;

namespace Fischost.Secrets;

/// <summary>The outcome of choosing a credential: a mode, or a problem naming variable NAMES only.</summary>
internal sealed record CredentialPlan(CredentialMode Mode, string? Problem)
{
    public bool IsOk => Problem is null && Mode != CredentialMode.None;
}

internal static class CredentialSelector
{
    public const string Tenant = "AZURE_TENANT_ID";
    public const string Client = "AZURE_CLIENT_ID";
    public const string Secret = "AZURE_CLIENT_SECRET";
    public const string CertPath = "AZURE_CLIENT_CERTIFICATE_PATH";
    public const string CertPassword = "AZURE_CLIENT_CERTIFICATE_PASSWORD";
    public const string SystemMi = "FISCHOST_SECRETS_MANAGED_IDENTITY";

    public static readonly string[] ReportedNames = [Tenant, Client, Secret, CertPath, CertPassword, SystemMi];

    private static bool Has(IReadOnlyDictionary<string, string?> vars, string name) =>
        vars.TryGetValue(name, out var v) && !string.IsNullOrWhiteSpace(v);

    /// <summary>Pure: decides from the variables given. Reads nothing from the process.</summary>
    public static CredentialPlan Choose(IReadOnlyDictionary<string, string?> vars, string environmentName, FischostSecretsOptions options)
    {
        bool dev = EnvironmentNames.IsDevelopment(environmentName);
        bool t = Has(vars, Tenant), c = Has(vars, Client), s = Has(vars, Secret), p = Has(vars, CertPath), pw = Has(vars, CertPassword);
        bool flag = Has(vars, SystemMi) && vars[SystemMi]!.Trim() == "1";

        if (pw && !p)
            return Partial([CertPath], CertPassword + " is set");
        if (p && s)
            return new(CredentialMode.None, $"ambiguous credential: both {CertPath} and {Secret} are set; keep only one");
        if (p)
        {
            var missing = new List<string>();
            if (!t) missing.Add(Tenant);
            if (!c) missing.Add(Client);
            return missing.Count > 0 ? Partial(missing, CertPath + " is set") : new(CredentialMode.Certificate, null);
        }
        if (t || s)
        {
            var missing = new List<string>();
            if (!t) missing.Add(Tenant);
            if (!c) missing.Add(Client);
            if (!s) missing.Add(Secret);
            return missing.Count > 0 ? Partial(missing, "some AZURE_* credential variables are set") : new(CredentialMode.ClientSecret, null);
        }
        if (c)
            return flag
                ? new(CredentialMode.ManagedIdentity, null) // user-assigned, by client id
                : new(CredentialMode.None, $"{Client} is set alone: set {SystemMi}=1 to use it as a user-assigned managed identity, or also set {Tenant} and {Secret}");

        // None of the AZURE_* credential variables is set.
        if (flag)
            return new(CredentialMode.ManagedIdentity, null); // system-assigned
        if (dev && options.AllowVaultInDevelopment && options.AllowDefaultAzureCredentialInDevelopment)
            return new(CredentialMode.DefaultAzure, null);
        return new(CredentialMode.None,
            $"no credential configured: set {Tenant}, {Client} and {Secret} (or {CertPath}), or {SystemMi}=1 for a managed identity (with {Client} for a user-assigned one)");
    }

    private static CredentialPlan Partial(List<string> missing, string why) =>
        new(CredentialMode.None, $"incomplete credential ({why}); missing: {string.Join(", ", missing)}");

    /// <summary>Edge: builds the credential. Values are read here, handed to the SDK, never kept or printed.</summary>
    public static TokenCredential Create(CredentialMode mode, Func<string, string?> read)
    {
        switch (mode)
        {
            case CredentialMode.Certificate:
            {
                var tenant = read(Tenant)!; var client = read(Client)!; var path = read(CertPath)!;
                var pwd = read(CertPassword);
                if (string.IsNullOrEmpty(pwd))
                    return new ClientCertificateCredential(tenant, client, path);
                var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12FromFile(path, pwd);
                return new ClientCertificateCredential(tenant, client, cert);
            }
            case CredentialMode.ClientSecret:
                return new ClientSecretCredential(read(Tenant)!, read(Client)!, read(Secret)!);
            case CredentialMode.ManagedIdentity:
                var id = read(Client);
                return string.IsNullOrWhiteSpace(id)
                    ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
                    : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(id));
            case CredentialMode.DefaultAzure:
                return new DefaultAzureCredential();
            default:
                throw new InvalidOperationException("No credential mode.");
        }
    }
}

internal static class EnvironmentNames
{
    public static bool IsDevelopment(string? n) => string.Equals(n?.Trim(), "Development", StringComparison.OrdinalIgnoreCase);
    public static bool IsProduction(string? n) => string.IsNullOrWhiteSpace(n) || string.Equals(n.Trim(), "Production", StringComparison.OrdinalIgnoreCase);
}
