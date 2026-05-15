using SecureVault.Api;
using SecureVault.Api.Auth.Jwt;
using SecureVault.Api.Validators;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

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

        app.MapPost("/login", async ([FromBody] AuthRequest req, UserManager<ApplicationUser> userManager, JwtTokenService jwtService, ApplicationDbContext db, JwtSettings jwtSettings) =>
        {            
            if (!InputValidator.ValidateUsernameAndPassword(req.UserName, req.Password, out var validationError))
            {
                return Results.BadRequest(validationError);
            }

            var user = await userManager.FindByNameAsync(req.UserName);
            if (user is null || !await userManager.CheckPasswordAsync(user, req.Password))
                return Results.Unauthorized();
            var accessToken = await jwtService.GenerateTokenAsync(user);
            var refreshToken = Guid.NewGuid().ToString();
            var expires = DateTime.UtcNow.AddMinutes(jwtSettings.ExpiresMinutes);
            db.RefreshTokens.Add(new RefreshToken(refreshToken, user.Id, expires, DateTime.UtcNow));
            await db.SaveChangesAsync();
            return Results.Ok(new AuthResponse(accessToken, refreshToken, expires));
        });

        app.MapPost("/refresh", async ([FromBody] RefreshRequest req, ApplicationDbContext db, UserManager<ApplicationUser> userManager, JwtTokenService jwtService, JwtSettings jwtSettings) =>
        {
            var token = await db.RefreshTokens.FindAsync(req.RefreshToken);
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
            return Results.Ok(new AuthResponse(newAccessToken, newRefreshToken, expires));
        });

        app.MapGet("/protected", () => "You are authenticated!").RequireAuthorization();

        app.MapGet("/admin-role", () => "You are an admin!").RequireAuthorization("AdminPolicy");
    }
}
