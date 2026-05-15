using Microsoft.AspNetCore.Components.WebAssembly.Http;
using System.Net;
using System.Net.Http.Json;
using SecureVault.Shared;

namespace SecureVault.Client;

public class CookieHandler : DelegatingHandler
{
    private readonly TokenService _tokenService;

    public CookieHandler(TokenService tokenService)
    {
        _tokenService = tokenService;
        InnerHandler = new HttpClientHandler();
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        request.SetBrowserRequestCredentials(BrowserRequestCredentials.Include);

        // Proactively refresh if token is expiring soon (within 30 seconds),
        // but skip the refresh endpoint itself to avoid infinite recursion
        var isRefreshEndpoint = request.RequestUri?.AbsolutePath.EndsWith("/refresh", StringComparison.OrdinalIgnoreCase) == true;
        if (!isRefreshEndpoint && _tokenService.IsExpiringSoon(TimeSpan.FromSeconds(30)))
        {
            await _tokenService.TryRefreshAsync(CreateRefreshClient(request.RequestUri));
        }

        var response = await base.SendAsync(request, cancellationToken);

        // Fallback: if we get a 401, attempt one refresh and retry
        if (response.StatusCode == HttpStatusCode.Unauthorized && !isRefreshEndpoint)
        {
            var refreshed = await _tokenService.TryRefreshAsync(CreateRefreshClient(request.RequestUri));
            if (refreshed)
            {
                // Clone and retry the original request
                var retryRequest = await CloneRequestAsync(request);
                retryRequest.SetBrowserRequestCredentials(BrowserRequestCredentials.Include);
                response = await base.SendAsync(retryRequest, cancellationToken);
            }
        }

        return response;
    }

    private static HttpClient CreateRefreshClient(Uri? baseUri)
    {
        var baseAddress = baseUri is not null
            ? new Uri(baseUri.GetLeftPart(UriPartial.Authority))
            : null;
        // Use a plain HttpClientHandler; BrowserRequestCredentials.Include is set
        // per-request inside TokenService via the PostAsJsonAsync call which goes
        // through a fresh handler — cookies are sent automatically by the browser
        // because the request targets the same origin.
        return new HttpClient(new HttpClientHandler()) { BaseAddress = baseAddress };
    }

    private static async Task<HttpRequestMessage> CloneRequestAsync(HttpRequestMessage original)
    {
        var clone = new HttpRequestMessage(original.Method, original.RequestUri);
        foreach (var header in original.Headers)
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

        if (original.Content is not null)
        {
            var bytes = await original.Content.ReadAsByteArrayAsync();
            clone.Content = new ByteArrayContent(bytes);
            foreach (var header in original.Content.Headers)
                clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        return clone;
    }
}
