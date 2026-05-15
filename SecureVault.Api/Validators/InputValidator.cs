using System.Text.RegularExpressions;

namespace SecureVault.Api.Validators;

/// <summary>
/// Core input validation logic to protect against XSS, SQL Injection, and other attacks
/// </summary>
public static class InputValidator
{
    private const int UsernameMinLength = 3;
    private const int UsernameMaxLength = 50;
    private const int PasswordMinLength = 8;
    private const int PasswordMaxLength = 128;

    /// <summary>
    /// XSS pattern detection - looks for common script tags and event handlers
    /// </summary>
    private static readonly Regex XssPattern = new(
        @"(<script|<iframe|<object|<embed|javascript:|onerror=|onload=|onclick=|on\w+\s*=)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

    /// <summary>
    /// SQL Injection pattern detection - looks for common SQL keywords and dangerous characters
    /// </summary>
    private static readonly Regex SqlInjectionPattern = new(
        @"('|(--|;|\/\*|\*\/|xp_|sp_|exec|execute|select|insert|update|delete|drop|create|alter|union|or\s+1\s*=\s*1))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

    /// <summary>
    /// Validates username and password against security threats and format requirements
    /// </summary>
    /// <param name="username">Username to validate</param>
    /// <param name="password">Password to validate</param>
    /// <param name="errorMessage">Output error message if validation fails</param>
    /// <returns>True if valid, false otherwise</returns>
    public static bool ValidateUsernameAndPassword(string? username, string? password, out string errorMessage)
    {
        // Validate username
        if (!ValidateUsername(username, out errorMessage))
        {
            return false;
        }

        // Validate password
        if (!ValidatePassword(password, out errorMessage))
        {
            return false;
        }

        errorMessage = string.Empty;
        return true;
    }

 
    public static bool ValidateUsername(string? username, out string errorMessage)
    {
        errorMessage = string.Empty;

        // Null or empty check
        if (string.IsNullOrWhiteSpace(username))
        {
            errorMessage = "Username cannot be empty.";
            return false;
        }

        username = username.Trim();

        // Length validation
        if (username.Length < UsernameMinLength)
        {
            errorMessage = $"Username must be at least {UsernameMinLength} characters long.";
            return false;
        }

        if (username.Length > UsernameMaxLength)
        {
            errorMessage = $"Username must not exceed {UsernameMaxLength} characters.";
            return false;
        }

        // XSS Detection
        if (ContainsXssPatterns(username))
        {
            errorMessage = "Username contains invalid characters or patterns.";
            return false;
        }

        // SQL Injection Detection
        if (ContainsSqlInjectionPatterns(username))
        {
            errorMessage = "Username contains invalid characters or patterns.";
            return false;
        }

        // Allow only alphanumeric, dots, hyphens, and underscores
        if (!Regex.IsMatch(username, @"^[a-zA-Z0-9._-]+$"))
        {
            errorMessage = "Username can only contain letters, numbers, dots, hyphens, and underscores.";
            return false;
        }

        return true;
    }
 
    public static bool ValidatePassword(string? password, out string errorMessage)
    {
        errorMessage = string.Empty;

        // Null or empty check
        if (string.IsNullOrWhiteSpace(password))
        {
            errorMessage = "Password cannot be empty.";
            return false;
        }

        // Length validation
        if (password.Length < PasswordMinLength)
        {
            errorMessage = $"Password must be at least {PasswordMinLength} characters long.";
            return false;
        }

        if (password.Length > PasswordMaxLength)
        {
            errorMessage = $"Password must not exceed {PasswordMaxLength} characters.";
            return false;
        }

        // XSS Detection
        if (ContainsXssPatterns(password))
        {
            errorMessage = "Password contains invalid patterns.";
            return false;
        }

        // SQL Injection Detection
        if (ContainsSqlInjectionPatterns(password))
        {
            errorMessage = "Password contains invalid patterns.";
            return false;
        }

        // Check for at least one uppercase letter
        if (!Regex.IsMatch(password, @"[A-Z]"))
        {
            errorMessage = "Password must contain at least one uppercase letter.";
            return false;
        }

        // Check for at least one lowercase letter
        if (!Regex.IsMatch(password, @"[a-z]"))
        {
            errorMessage = "Password must contain at least one lowercase letter.";
            return false;
        }

        // Check for at least one digit
        if (!Regex.IsMatch(password, @"[0-9]"))
        {
            errorMessage = "Password must contain at least one number.";
            return false;
        }

        // Check for at least one special character
        if (!Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':"",.<>?/\\|`~]"))
        {
            errorMessage = "Password must contain at least one special character.";
            return false;
        }

        return true;
    }
    
    public static bool ValidateUserRole(string? newUserRole, string? endpoint, out string errorMessage)
    {
        errorMessage = string.Empty;
        if (string.IsNullOrWhiteSpace(newUserRole))
        {
            errorMessage = "Role cannot be empty.";
            return false;
        }
        newUserRole = newUserRole.Trim();
        
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            errorMessage = "Endpoint cannot be empty.";
            return false;
        }

        switch (endpoint)
        {
            case "/register":
                if (newUserRole != nameof(UserRoles.User) && newUserRole != nameof(UserRoles.Guest))
                {
                    errorMessage = $"Invalid role. Can only register as {nameof(UserRoles.User)} or {nameof(UserRoles.Guest)}.";
                    return false;
                }
                break;

            case "/register-admin":
                if (newUserRole != nameof(UserRoles.Admin))
                {
                    errorMessage = $"Invalid role. Can only register users as {nameof(UserRoles.Admin)}.";
                    return false;
                }
                break;

            default:
                errorMessage = "Invalid endpoint for role assignment.";
                return false;
        }
        return true;
    }

    /// <summary>
    /// Checks if input contains XSS patterns
    /// </summary>
    private static bool ContainsXssPatterns(string input)
    {
        return XssPattern.IsMatch(input);
    }

    /// <summary>
    /// Checks if input contains SQL Injection patterns
    /// </summary>
    private static bool ContainsSqlInjectionPatterns(string input)
    {
        return SqlInjectionPattern.IsMatch(input);
    }
}
