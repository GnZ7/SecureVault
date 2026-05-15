namespace SecureVault.Shared;

public sealed record RegisterRequest(string UserName, string Password, string Role);
public sealed record AuthRequest(string UserName, string Password);
public sealed record AuthResponse(string AccessToken, string RefreshToken, DateTime ExpiresAt);
public sealed record RefreshRequest(string RefreshToken);
