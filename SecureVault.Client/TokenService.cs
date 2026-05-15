using System.Net.Http.Json;
using Microsoft.AspNetCore.Components.WebAssembly.Http;
using SecureVault.Shared;

namespace SecureVault.Client;

public class TokenService
{
    private DateTime _expiresAt = DateTime.MinValue;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    public void SetExpiry(DateTime expiresAt) => _expiresAt = expiresAt;

    public bool IsExpiringSoon(TimeSpan threshold) =>
        _expiresAt == DateTime.MinValue || DateTime.UtcNow >= _expiresAt - threshold;

    protected virtual HttpRequestMessage BuildRefreshRequest()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/refresh");
        // BrowserRequestCredentials.Include is required in Blazor WASM so the
        // browser sends HttpOnly cookies cross-origin to the API.
        request.SetBrowserRequestCredentials(BrowserRequestCredentials.Include);
        return request;
    }

    public async Task<bool> TryRefreshAsync(HttpClient httpClient)
    {
        await _refreshLock.WaitAsync();
        try
        {
            // Double-check after acquiring lock — another request may have already refreshed
            if (!IsExpiringSoon(TimeSpan.FromSeconds(30)))
                return true;

            var request = BuildRefreshRequest();
            request.Content = JsonContent.Create(new RefreshRequest(string.Empty));

            var response = await httpClient.SendAsync(request);
            if (!response.IsSuccessStatusCode)
                return false;

            var auth = await response.Content.ReadFromJsonAsync<AuthResponse>();
            if (auth is null)
                return false;

            _expiresAt = auth.ExpiresAt;
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            _refreshLock.Release();
        }
    }
}
