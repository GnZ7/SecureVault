using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureVault.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using SecureVault.Api.Auth.Jwt;
using SecureVault.Api.Auth;

var builder = WebApplication.CreateBuilder(args);

// JWT settings
var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>() ?? throw new InvalidOperationException("JWT settings are not configured properly.");
builder.Services.AddSingleton(jwtSettings);

builder.Services.AddScoped<JwtTokenService>();

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite("Data Source=localdb.sqlite"));
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidAudience = jwtSettings.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key)),
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("SuperAdminPolicy", policy => policy.RequireRole(nameof(UserRoles.SuperAdmin)))
    .AddPolicy("AdminPolicy", policy => policy.RequireRole("Admin"))
    .AddPolicy("UserPolicy", policy => policy.RequireRole("User")); ;

var app = builder.Build();

await SeedDbAsync(app.Services);

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

AuthEndpoints.MapAuthEndpoints(app);

app.Run();

async Task SeedDbAsync(IServiceProvider serviceProvider)
{    
    await EnsureMigrationsAsync(serviceProvider);
    await SeedRolesAsync(serviceProvider);
    await SeedSuperAdminUserAsync(serviceProvider);
}

async Task EnsureMigrationsAsync(IServiceProvider serviceProvider)
{
    using var scope = serviceProvider.CreateScope();
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await context.Database.EnsureCreatedAsync();
    await context.Database.MigrateAsync();
}

async Task SeedRolesAsync(IServiceProvider serviceProvider)
{
    using var scope = serviceProvider.CreateScope();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();    

    foreach (var roleName in Enum.GetNames<UserRoles>())
    {
        if (!await roleManager.RoleExistsAsync(roleName))
        {
            await roleManager.CreateAsync(new IdentityRole(roleName));
        }
    }
}

async Task SeedSuperAdminUserAsync(IServiceProvider serviceProvider)
{    
    using var scope = serviceProvider.CreateScope();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

    var superAdminUser = await userManager.FindByNameAsync("superadmin");
    
    if (superAdminUser != null)
    {
        var roles = await userManager.GetRolesAsync(superAdminUser);
        if (!roles.Contains(nameof(UserRoles.SuperAdmin)))
        {
            await userManager.AddToRoleAsync(superAdminUser, nameof(UserRoles.SuperAdmin));
        }
    }
    else
    {
        var password = builder.Configuration["DefaultSuperAdminPassword"] ??
            throw new InvalidOperationException("Default super admin password is not configured.");
        var user = new ApplicationUser { UserName = "superadmin" };
        var result = await userManager.CreateAsync(user, password);
        if (!result.Succeeded)
        {
            throw new Exception("Failed to create default super admin user: " + string.Join(", ", result.Errors.Select(e => e.Description)));
        }
        await userManager.AddToRoleAsync(user, nameof(UserRoles.SuperAdmin));
                
    }
}