using SecureVault.Api.Validators;

namespace SecureVault.Tests.Validators;

public class InputValidatorTests
{
    /* ---------------------------
     * SQL INJECTION TESTS
     * --------------------------- */

    [Theory]
    [InlineData("admin' OR 1=1 --")]
    [InlineData("admin'; DROP TABLE Users; --")]
    [InlineData("admin\" OR \"1\"=\"1")]
    [InlineData("admin; SELECT * FROM Users")]
    [InlineData("admin UNION SELECT password FROM users")]
    [InlineData("admin--")]
    [InlineData("admin&#39; OR 1=1 --")]
    public void Username_WithSqlInjection_ShouldFail(string maliciousUsername)
    {
        // Act
        var isValid = InputValidator.ValidateUsernameAndPassword(
            maliciousUsername,
            "ValidPass1!",
            out var errorMessage
        );

        // Assert
        Assert.False(isValid);
        Assert.NotEmpty(errorMessage);
    }

    [Theory]
    [InlineData("Password1!' OR 1=1 --")]
    [InlineData("Password1!; DROP TABLE Users")]
    [InlineData("Password1! UNION SELECT * FROM users")]
    public void Password_WithSqlInjection_ShouldFail(string maliciousPassword)
    {
        // Act
        var isValid = InputValidator.ValidateUsernameAndPassword(
            "validUser",
            maliciousPassword,
            out var errorMessage
        );

        // Assert
        Assert.False(isValid);
        Assert.NotEmpty(errorMessage);
    }

    /* ---------------------------
     * XSS ATTACK TESTS
     * --------------------------- */

    [Theory]
    [InlineData("<script>alert('xss')</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("<iframe src='javascript:alert(1)'></iframe>")]
    [InlineData("<div onclick='alert(1)'>click</div>")]
    [InlineData("javascript:alert(1)")]
    [InlineData("&lt;script&gt;alert('xss')&lt;/script&gt;")]
    public void Username_WithXssPayload_ShouldFail(string maliciousUsername)
    {
        // Act
        var isValid = InputValidator.ValidateUsernameAndPassword(
            maliciousUsername,
            "ValidPass1!",
            out var errorMessage
        );

        // Assert
        Assert.False(isValid);
        Assert.NotEmpty(errorMessage);
    }

    [Theory]
    [InlineData("<script>alert('xss')</script>Valid1!")]
    [InlineData("Valid1!<img src=x onerror=alert(1)>")]
    [InlineData("Valid1!javascript:alert(1)")]
    public void Password_WithXssPayload_ShouldFail(string maliciousPassword)
    {
        // Act
        var isValid = InputValidator.ValidateUsernameAndPassword(
            "validUser",
            maliciousPassword,
            out var errorMessage
        );

        // Assert
        Assert.False(isValid);
        Assert.NotEmpty(errorMessage);
    }

    /* ---------------------------
     * CONTROL / POSITIVE CASES
     * --------------------------- */

    [Fact]
    public void ValidUsernameAndPassword_ShouldPass()
    {
        // Act
        var isValid = InputValidator.ValidateUsernameAndPassword(
            "valid.user_123",
            "StrongPass1!",
            out var errorMessage
        );

        // Assert
        Assert.True(isValid);
        Assert.Equal(string.Empty, errorMessage);
    }

    [Theory]
    [InlineData("ab")]               // Too short
    [InlineData("thisusernameiswaytoolongtobeacceptedbythesystem6666")]
    [InlineData("user name")]        // Space not allowed
    [InlineData("user@name")]        // Invalid char
    public void InvalidUsername_Format_ShouldFail(string username)
    {
        // Act
        var isValid = InputValidator.ValidateUsernameAndPassword(
            username,
            "StrongPass1!",
            out var errorMessage
        );

        // Assert
        Assert.False(isValid);
        Assert.NotEmpty(errorMessage);
    }
}