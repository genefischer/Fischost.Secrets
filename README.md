# Fischost.Secrets

A tiny helper to fetch secrets from **Azure Key Vault** without cluttering your `Program.cs`.

## Environment Variables

Set on the machine (PC & VPS):

- `KEYVAULT_URL`  → e.g. `https://homefixervault.vault.azure.net/`  
- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` when **not** using Managed Identity (on‑prem/VPS).

**PowerShell (Machine scope):**
```powershell
[Environment]::SetEnvironmentVariable("KEYVAULT_URL","https://homefixervault.vault.azure.net/","Machine")
[Environment]::SetEnvironmentVariable("AZURE_TENANT_ID","<tenant-guid>","Machine")
[Environment]::SetEnvironmentVariable("AZURE_CLIENT_ID","<app-guid>","Machine")
[Environment]::SetEnvironmentVariable("AZURE_CLIENT_SECRET","<client-secret-VALUE>","Machine")
```

Restart your service (or VS) after setting them.

## Usage in Program.cs

```csharp
using Fischost.Secrets;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// initialize once
Secrets.InitFromEnv();

if (builder.Environment.IsDevelopment())
{
    Secrets.DumpDiagnostics(msg => Console.WriteLine($"[Secrets] {msg}"));
}

// EF Core
builder.Services.AddDbContext<DataContext>(options =>
{
    var conn = Secrets.Get("ConnectionStringHomeFixer");
    options.UseSqlServer(conn);
});

// Stripe
builder.Services.Configure<StripeSettings>(o =>
{
    o.ApiKey = Secrets.Get("StripeApiKey");
});

// JWT
var jwtKey = Secrets.Get("JwtSecurityKey");
// if stored as BASE64: var keyBytes = Convert.FromBase64String(jwtKey);
var keyBytes = Encoding.UTF8.GetBytes(jwtKey);
var signingKey = new SymmetricSecurityKey(keyBytes);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["JwtIssuer"],
            ValidAudience = builder.Configuration["JwtAudience"],
            IssuerSigningKey = signingKey
        };
    });
```
