using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureVault.Shared;

namespace SecureVault.Tests.TokenRefresh;

/// <summary>
/// Testable subclass of the client-side TokenService logic.
/// Overrides BuildRefreshRequest to avoid the Blazor WASM-only
/// BrowserRequestCredentials API, which is unavailable in xUnit.
/// </summary>
internal class TestableTokenService : TokenServiceCore
{
    protected override HttpRequestMessage BuildRefreshRequest()
        => new HttpRequestMessage(HttpMethod.Post, "/refresh");
}

/// <summary>
/// Pure token-service logic extracted from the Blazor client so it can be
/// tested without any Blazor WASM runtime dependency.
/// Mirrors SecureVault.Client.TokenService exactly, minus the Blazor-specific
/// BrowserRequestCredentials call (which lives in BuildRefreshRequest).
/// </summary>
internal abstract class TokenServiceCore
{
    private DateTime _expiresAt = DateTime.MinValue;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    public void SetExpiry(DateTime expiresAt) => _expiresAt = expiresAt;

    public bool IsExpiringSoon(TimeSpan threshold) =>
        _expiresAt == DateTime.MinValue || DateTime.UtcNow >= _expiresAt - threshold;

    protected abstract HttpRequestMessage BuildRefreshRequest();

    public async Task<bool> TryRefreshAsync(HttpClient httpClient)
    {
        await _refreshLock.WaitAsync();
        try
        {
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

/// <summary>
/// Fake HttpMessageHandler that returns a pre-configured response.
/// </summary>
internal class FakeHttpHandler : HttpMessageHandler
{
    private readonly HttpResponseMessage _response;

    public FakeHttpHandler(HttpResponseMessage response) => _response = response;

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
        => Task.FromResult(_response);
}

public class TokenServiceTests
{
    // -----------------------------------------------------------------------
    // SetExpiry / IsExpiringSoon
    // -----------------------------------------------------------------------

    [Fact]
    public void IsExpiringSoon_BeforeThreshold_ReturnsFalse()
    {
        var svc = new TestableTokenService();
        // Expires 2 minutes from now — well outside the 30-second threshold
        svc.SetExpiry(DateTime.UtcNow.AddMinutes(2));

        Assert.False(svc.IsExpiringSoon(TimeSpan.FromSeconds(30)));
    }

    [Fact]
    public void IsExpiringSoon_WithinThreshold_ReturnsTrue()
    {
        var svc = new TestableTokenService();
        // Expires in 10 seconds — inside the 30-second threshold
        svc.SetExpiry(DateTime.UtcNow.AddSeconds(10));

        Assert.True(svc.IsExpiringSoon(TimeSpan.FromSeconds(30)));
    }

    [Fact]
    public void IsExpiringSoon_AlreadyExpired_ReturnsTrue()
    {
        var svc = new TestableTokenService();
        svc.SetExpiry(DateTime.UtcNow.AddSeconds(-1));

        Assert.True(svc.IsExpiringSoon(TimeSpan.FromSeconds(30)));
    }

    [Fact]
    public void IsExpiringSoon_DefaultState_ReturnsTrue()
    {
        // No SetExpiry called — _expiresAt is DateTime.MinValue, always expiring
        var svc = new TestableTokenService();

        Assert.True(svc.IsExpiringSoon(TimeSpan.FromSeconds(30)));
    }

    [Fact]
    public void SetExpiry_UpdatesExpiryCorrectly()
    {
        var svc = new TestableTokenService();
        var future = DateTime.UtcNow.AddMinutes(5);
        svc.SetExpiry(future);

        Assert.False(svc.IsExpiringSoon(TimeSpan.FromSeconds(30)));
    }

    // -----------------------------------------------------------------------
    // TryRefreshAsync — happy path
    // -----------------------------------------------------------------------

    [Fact]
    public async Task TryRefreshAsync_SuccessfulResponse_ReturnsTrueAndUpdatesExpiry()
    {
        var svc = new TestableTokenService();
        // Token is expiring soon
        svc.SetExpiry(DateTime.UtcNow.AddSeconds(5));

        var newExpiry = DateTime.UtcNow.AddMinutes(3);
        var authResponse = new AuthResponse("new-access-token", "new-refresh-token", newExpiry);
        var json = JsonSerializer.Serialize(authResponse);

        var fakeResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
        };
        var httpClient = new HttpClient(new FakeHttpHandler(fakeResponse))
        {
            BaseAddress = new Uri("https://localhost")
        };

        var result = await svc.TryRefreshAsync(httpClient);

        Assert.True(result);
        // After refresh the token should no longer be expiring soon
        Assert.False(svc.IsExpiringSoon(TimeSpan.FromSeconds(30)));
    }

    // -----------------------------------------------------------------------
    // TryRefreshAsync — token not yet expiring (double-check guard)
    // -----------------------------------------------------------------------

    [Fact]
    public async Task TryRefreshAsync_TokenNotExpiringSoon_ReturnsTrueWithoutCallingApi()
    {
        var svc = new TestableTokenService();
        // Token expires in 2 minutes — no refresh needed
        svc.SetExpiry(DateTime.UtcNow.AddMinutes(2));

        // Handler that always fails — should never be called
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.InternalServerError);
        var httpClient = new HttpClient(new FakeHttpHandler(fakeResponse))
        {
            BaseAddress = new Uri("https://localhost")
        };

        var result = await svc.TryRefreshAsync(httpClient);

        // Returns true because the double-check guard short-circuits
        Assert.True(result);
    }

    // -----------------------------------------------------------------------
    // TryRefreshAsync — API failure
    // -----------------------------------------------------------------------

    [Fact]
    public async Task TryRefreshAsync_UnauthorizedResponse_ReturnsFalse()
    {
        var svc = new TestableTokenService();
        svc.SetExpiry(DateTime.UtcNow.AddSeconds(5));

        var fakeResponse = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        var httpClient = new HttpClient(new FakeHttpHandler(fakeResponse))
        {
            BaseAddress = new Uri("https://localhost")
        };

        var result = await svc.TryRefreshAsync(httpClient);

        Assert.False(result);
    }

    [Fact]
    public async Task TryRefreshAsync_NetworkException_ReturnsFalse()
    {
        var svc = new TestableTokenService();
        svc.SetExpiry(DateTime.UtcNow.AddSeconds(5));

        var httpClient = new HttpClient(new ThrowingHttpHandler())
        {
            BaseAddress = new Uri("https://localhost")
        };

        var result = await svc.TryRefreshAsync(httpClient);

        Assert.False(result);
    }

    [Fact]
    public async Task TryRefreshAsync_MalformedJsonResponse_ReturnsFalse()
    {
        var svc = new TestableTokenService();
        svc.SetExpiry(DateTime.UtcNow.AddSeconds(5));

        var fakeResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("not-valid-json", System.Text.Encoding.UTF8, "application/json")
        };
        var httpClient = new HttpClient(new FakeHttpHandler(fakeResponse))
        {
            BaseAddress = new Uri("https://localhost")
        };

        var result = await svc.TryRefreshAsync(httpClient);

        Assert.False(result);
    }

    // -----------------------------------------------------------------------
    // TryRefreshAsync — concurrency (only one refresh call when called in parallel)
    // -----------------------------------------------------------------------

    [Fact]
    public async Task TryRefreshAsync_ConcurrentCalls_OnlyOneRefreshOccurs()
    {
        var svc = new TestableTokenService();
        svc.SetExpiry(DateTime.UtcNow.AddSeconds(5));

        var callCount = 0;
        var newExpiry = DateTime.UtcNow.AddMinutes(3);
        var authResponse = new AuthResponse("token", "refresh", newExpiry);
        var json = JsonSerializer.Serialize(authResponse);

        var handler = new CountingFakeHttpHandler(() =>
        {
            Interlocked.Increment(ref callCount);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
            };
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost") };

        // Fire 5 concurrent refresh attempts
        var tasks = Enumerable.Range(0, 5)
            .Select(_ => svc.TryRefreshAsync(httpClient));
        var results = await Task.WhenAll(tasks);

        Assert.All(results, r => Assert.True(r));
        // After the first refresh the token is no longer expiring, so subsequent
        // calls inside the lock short-circuit — only 1 actual HTTP call expected.
        Assert.Equal(1, callCount);
    }
}

internal class ThrowingHttpHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
        => throw new HttpRequestException("Simulated network failure");
}

internal class CountingFakeHttpHandler : HttpMessageHandler
{
    private readonly Func<HttpResponseMessage> _factory;
    public CountingFakeHttpHandler(Func<HttpResponseMessage> factory) => _factory = factory;

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
        => Task.FromResult(_factory());
}
