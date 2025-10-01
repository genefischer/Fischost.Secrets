using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace Fischost.Secrets
{
    /// <summary>
    /// Super-light helper to read secrets from Azure Key Vault with minimal wiring.
    /// </summary>
    public static class Secrets
    {
        private static SecretClient? _client;
        private static string? _vaultUrl;
        private static string _authMode = "Uninitialized";

        /// <summary>
        /// Initialize using environment variables.
        /// Requires KEYVAULT_URL; and either Managed Identity OR
        /// AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET.
        /// </summary>
        public static void InitFromEnv()
        {
            var vaultUrl = Environment.GetEnvironmentVariable("KEYVAULT_URL");
            if (string.IsNullOrWhiteSpace(vaultUrl))
                throw new InvalidOperationException("KEYVAULT_URL is not set.");

            var tenantId = Environment.GetEnvironmentVariable("AZURE_TENANT_ID");
            var clientId = Environment.GetEnvironmentVariable("AZURE_CLIENT_ID");
            var clientSecret = Environment.GetEnvironmentVariable("AZURE_CLIENT_SECRET");

            TokenCredential credential;

            if (!string.IsNullOrWhiteSpace(tenantId) &&
                !string.IsNullOrWhiteSpace(clientId) &&
                !string.IsNullOrWhiteSpace(clientSecret))
            {
                _authMode = "ClientSecretCredential";
                credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
            }
            else
            {
                // Works on dev boxes (Visual Studio, Azure CLI), Azure-hosted with Managed Identity, etc.
                _authMode = "DefaultAzureCredential";
                credential = new DefaultAzureCredential();
            }

            _client = new SecretClient(new Uri(vaultUrl), credential);
            _vaultUrl = vaultUrl;
        }

        /// <summary>
        /// Initialize explicitly with a client secret (for non-Azure servers).
        /// </summary>
        public static void InitWithClientSecret(string vaultUrl, string tenantId, string clientId, string clientSecret)
        {
            if (string.IsNullOrWhiteSpace(vaultUrl)) throw new ArgumentNullException(nameof(vaultUrl));
            if (string.IsNullOrWhiteSpace(tenantId)) throw new ArgumentNullException(nameof(tenantId));
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new ArgumentNullException(nameof(clientSecret));

            var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
            _client = new SecretClient(new Uri(vaultUrl), credential);
            _vaultUrl = vaultUrl;
            _authMode = "ClientSecretCredential";
        }

        /// <summary>
        /// Get a secret value by name. Throws if not found.
        /// </summary>
        public static string Get(string name)
        {
            EnsureInitialized();
            try
            {
                var resp = _client!.GetSecret(name);
                return resp.Value.Value;
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 404)
            {
                throw new InvalidOperationException($"Secret '{name}' not found in Key Vault {_vaultUrl}.", ex);
            }
        }

        /// <summary>
        /// Try to get a secret value by name; returns false if missing.
        /// </summary>
        public static bool TryGet(string name, out string? value)
        {
            EnsureInitialized();
            try
            {
                var resp = _client!.GetSecret(name);
                value = resp.Value.Value;
                return true;
            }
            catch
            {
                value = null;
                return false;
            }
        }

        /// <summary>
        /// Writes safe diagnostics (never prints secret values).
        /// </summary>
        public static void DumpDiagnostics(Action<string> writeLine)
        {
            writeLine($"Vault URL: {_vaultUrl ?? "(not set)"}");
            writeLine($"Auth mode: {_authMode}");
            writeLine("Env present: " +
                      $"AZURE_TENANT_ID={(EnvSet("AZURE_TENANT_ID") ? "Y" : "N")}, " +
                      $"AZURE_CLIENT_ID={(EnvSet("AZURE_CLIENT_ID") ? "Y" : "N")}, " +
                      $"AZURE_CLIENT_SECRET={(EnvSet("AZURE_CLIENT_SECRET") ? "Y" : "N")}");
        }

        private static bool EnvSet(string n) => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(n));

        private static void EnsureInitialized()
        {
            if (_client is null)
                throw new InvalidOperationException("Fischost.Secrets not initialized. Call Secrets.InitFromEnv() or Secrets.InitWithClientSecret(...) first.");
        }
    }
}
