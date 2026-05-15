using SecureVault.Api.Auth.Jwt;

namespace SecureVault.Tests.TokenRefresh;

public class RefreshTokenTests
{
    // -----------------------------------------------------------------------
    // IsExpired
    // -----------------------------------------------------------------------

    [Fact]
    public void IsExpired_WhenExpiryIsInFuture_ReturnsFalse()
    {
        var token = new RefreshToken("tok1", "user1", DateTime.UtcNow.AddMinutes(5), DateTime.UtcNow);

        Assert.False(token.IsExpired);
    }

    [Fact]
    public void IsExpired_WhenExpiryIsInPast_ReturnsTrue()
    {
        var token = new RefreshToken("tok2", "user1", DateTime.UtcNow.AddSeconds(-1), DateTime.UtcNow);

        Assert.True(token.IsExpired);
    }

    // -----------------------------------------------------------------------
    // IsActive
    // -----------------------------------------------------------------------

    [Fact]
    public void IsActive_WhenNotRevokedAndNotExpired_ReturnsTrue()
    {
        var token = new RefreshToken("tok3", "user1", DateTime.UtcNow.AddMinutes(3), DateTime.UtcNow);

        Assert.True(token.IsActive);
    }

    [Fact]
    public void IsActive_WhenRevoked_ReturnsFalse()
    {
        var token = new RefreshToken("tok4", "user1", DateTime.UtcNow.AddMinutes(3), DateTime.UtcNow,
            Revoked: DateTime.UtcNow);

        Assert.False(token.IsActive);
    }

    [Fact]
    public void IsActive_WhenExpiredAndNotRevoked_ReturnsFalse()
    {
        var token = new RefreshToken("tok5", "user1", DateTime.UtcNow.AddSeconds(-1), DateTime.UtcNow);

        Assert.False(token.IsActive);
    }

    [Fact]
    public void IsActive_WhenRevokedAndExpired_ReturnsFalse()
    {
        var token = new RefreshToken("tok6", "user1", DateTime.UtcNow.AddSeconds(-1), DateTime.UtcNow,
            Revoked: DateTime.UtcNow.AddSeconds(-30));

        Assert.False(token.IsActive);
    }

    // -----------------------------------------------------------------------
    // Token expiry boundary — simulating the 3-minute window used by the API
    // -----------------------------------------------------------------------

    [Fact]
    public void RefreshToken_CreatedWithThreeMinuteExpiry_IsActiveImmediately()
    {
        var expires = DateTime.UtcNow.AddMinutes(3);
        var token = new RefreshToken("tok7", "user1", expires, DateTime.UtcNow);

        Assert.True(token.IsActive);
        Assert.False(token.IsExpired);
    }

    [Fact]
    public void RefreshToken_AfterExpiryWindow_IsNoLongerActive()
    {
        // Simulate a token whose 3-minute window has already elapsed
        var expires = DateTime.UtcNow.AddMinutes(-3);
        var token = new RefreshToken("tok8", "user1", expires, DateTime.UtcNow.AddMinutes(-6));

        Assert.False(token.IsActive);
        Assert.True(token.IsExpired);
    }
}
