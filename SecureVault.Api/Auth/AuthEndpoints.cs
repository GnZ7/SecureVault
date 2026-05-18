using SecureVault.Api;
using SecureVault.Api.Auth.Jwt;
using SecureVault.Api.Validators;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace SecureVault.Api.Auth;

public class AuthEndpoints
{
    public static void MapAuthEndpoints(WebApplication app)
    {
        app.MapPost("/register", async ([FromBody] RegisterRequest req, UserManager<ApplicationUser> userManager, HttpContext httpContext) =>
        {            
            if (!InputValidator.ValidateUsername(req.UserName, out var usernameValidationError))
            {
                return Results.BadRequest(usernameValidationError);
            }

            if (!InputValidator.ValidatePassword(req.Password, out var passwordValidationError))
            {
                return Results.BadRequest(passwordValidationError);
            }

            if (!InputValidator.ValidateUserRole(req.Role, httpContext.Request.Path.Value, out var roleValidationError))
            {
                return Results.Forbid();
            }           

            var user = new ApplicationUser { UserName = req.UserName };

            var result = await userManager.CreateAsync(user, req.Password);

            if (!result.Succeeded)
                return Results.BadRequest(result.Errors);            


            var roleResult = await userManager.AddToRoleAsync(user, req.Role);
            if (!roleResult.Succeeded)
                return Results.BadRequest(roleResult.Errors);

            return Results.Ok();
        });

        // Only SuperAdmin can create Admin users
        app.MapPost("/register-admin", async ([FromBody] RegisterRequest req, UserManager<ApplicationUser> userManager, HttpContext httpContext) =>
        {
            if (!InputValidator.ValidateUsername(req.UserName, out var usernameValidationError))
            {
                return Results.BadRequest(usernameValidationError);
            }

            if (!InputValidator.ValidatePassword(req.Password, out var passwordValidationError))
            {
                return Results.BadRequest(passwordValidationError);
            }

            if (!InputValidator.ValidateUserRole(req.Role, httpContext.Request.Path.Value, out var roleValidationError))
            {
                return Results.Forbid();
            }

            var user = new ApplicationUser { UserName = req.UserName };

            var result = await userManager.CreateAsync(user, req.Password);

            if (!result.Succeeded)
                return Results.BadRequest(result.Errors);


            var roleResult = await userManager.AddToRoleAsync(user, req.Role);
            if (!roleResult.Succeeded)
                return Results.BadRequest(roleResult.Errors);

            return Results.Ok();
        })
        .RequireAuthorization("SuperAdminPolicy");

        app.MapPost("/login", async ([FromBody] AuthRequest req, UserManager<ApplicationUser> userManager, JwtTokenService jwtService, ApplicationDbContext db, JwtSettings jwtSettings, HttpContext httpContext, ILogger<AuthEndpoints> logger) =>
        {            
            if (!InputValidator.ValidateUsernameAndPassword(req.UserName, req.Password, out var validationError))
            {
                logger.LogWarning("Login rejected due to invalid input for user '{UserName}' from IP {IpAddress}.", req.UserName, httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
                return Results.BadRequest(validationError);
            }

            var user = await userManager.FindByNameAsync(req.UserName);
            if (user is null || !await userManager.CheckPasswordAsync(user, req.Password))
            {
                logger.LogWarning("Login failed for user '{UserName}' from IP {IpAddress}.", req.UserName, httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
                return Results.Unauthorized();
            }

            logger.LogInformation("Login succeeded for user '{UserName}' from IP {IpAddress}.", req.UserName, httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");

            var accessToken = await jwtService.GenerateTokenAsync(user);
            var refreshToken = Guid.NewGuid().ToString();
            var expires = DateTime.UtcNow.AddMinutes(jwtSettings.ExpiresMinutes);
            db.RefreshTokens.Add(new RefreshToken(refreshToken, user.Id, expires, DateTime.UtcNow));
            await db.SaveChangesAsync();

            httpContext.Response.Cookies.Append("accessToken", accessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = expires
            });

            httpContext.Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = expires
            });

            return Results.Ok(new AuthResponse(accessToken, refreshToken, expires));
        });

        app.MapPost("/refresh", async ([FromBody] RefreshRequest req, ApplicationDbContext db, UserManager<ApplicationUser> userManager, JwtTokenService jwtService, JwtSettings jwtSettings, HttpContext httpContext) =>
        {
            var refreshTokenValue = req.RefreshToken ?? httpContext.Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshTokenValue))
                return Results.Unauthorized();

            var token = await db.RefreshTokens.FindAsync(refreshTokenValue);
            if (token is null || !token.IsActive)
                return Results.Unauthorized();
            var user = await userManager.FindByIdAsync(token.UserId);
            if (user is null)
                return Results.Unauthorized();
            // Revoke old token
            db.RefreshTokens.Remove(token);
            // Issue new tokens
            var newAccessToken = await jwtService.GenerateTokenAsync(user);
            var newRefreshToken = Guid.NewGuid().ToString();
            var expires = DateTime.UtcNow.AddMinutes(jwtSettings.ExpiresMinutes);
            db.RefreshTokens.Add(new RefreshToken(newRefreshToken, user.Id, expires, DateTime.UtcNow));
            await db.SaveChangesAsync();

            httpContext.Response.Cookies.Append("accessToken", newAccessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = expires
            });

            httpContext.Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = expires
            });

            return Results.Ok(new AuthResponse(newAccessToken, newRefreshToken, expires));
        });

        app.MapPost("/logout", (HttpContext httpContext) =>
        {
            httpContext.Response.Cookies.Delete("accessToken");
            httpContext.Response.Cookies.Delete("refreshToken");
            return Results.Ok();
        });

        app.MapGet("/userinfo", (ClaimsPrincipal user) =>
        {
            if (user.Identity?.IsAuthenticated != true)
                return Results.Unauthorized();

            var claims = user.Claims.Select(c => new { c.Type, c.Value });
            return Results.Ok(new { user.Identity.Name, Claims = claims });
        }).RequireAuthorization();

        app.MapGet("/protected", () => "You are authenticated!").RequireAuthorization();

        app.MapGet("/admin-role", () => "You are an admin!").RequireAuthorization("AdminPolicy");
    }
}
