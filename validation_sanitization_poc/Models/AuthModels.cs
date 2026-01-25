using System.ComponentModel.DataAnnotations;

namespace validation_sanitization_poc.Models;

/// <summary>
/// Login Request Model
/// </summary>
public class LoginRequest
{
    [Required(ErrorMessage = "Username is required.")]
    public string Username { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    public string Password { get; set; }
}

/// <summary>
/// Represents a user who has successfully authenticated within the system.
/// </summary>
/// <remarks>This class provides information about the authenticated user, including their unique identifier,
/// username, role, and authentication details such as whether they have administrative privileges and the time of their
/// login.</remarks>
public class AuthenticatedUser
{
    public string UserId { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public bool IsAdmin { get; set; }
    public DateTime LoginTime { get; set; }
}


/// <summary>
/// Represents the response returned after a login attempt.
/// </summary>
/// <remarks>This class encapsulates the result of a login operation, including whether the login was successful, 
/// an optional message providing additional context, and the authenticated user details if the login
/// succeeded.</remarks>
public class LoginResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public AuthenticatedUser? User { get; set; }
}
