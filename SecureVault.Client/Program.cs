using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.AspNetCore.Components.WebAssembly.Http;
using System.Text.Json;
using SecureVault.Client;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Load API base address from appsettings.json
var apiBaseAddress = builder.Configuration["ApiBaseAddress"] ?? throw new InvalidOperationException("API base address is not configured");

builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped(sp => 
{
    var tokenService = sp.GetRequiredService<TokenService>();
    var handler = new CookieHandler(tokenService);
    var httpClient = new HttpClient(handler) { BaseAddress = new Uri(apiBaseAddress) };
    return httpClient;
});

await builder.Build().RunAsync();
