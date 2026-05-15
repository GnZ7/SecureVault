using System.ComponentModel.DataAnnotations;

namespace SecureVault.Api.Auth.Jwt;

public sealed record RefreshToken(
    [property: Key] string Token,
    string UserId,
    DateTime Expires,
    DateTime Created,
    DateTime? Revoked = null
)
{
    public bool IsActive => Revoked == null && !IsExpired;
    public bool IsExpired => DateTime.UtcNow >= Expires;
}
