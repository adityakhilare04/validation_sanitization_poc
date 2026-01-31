using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using validation_sanitization_poc.Filters;
using validation_sanitization_poc.Models;

namespace validation_sanitization_poc.Controllers;

[Route("api/[controller]")]
[ApiController]
[Produces("application/json")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private const string AUTH_COOKIE_NAME = "AuthToken";

    private static readonly Dictionary<string, (string Password, string Role, bool IsAdmin)> Users = new()
    {
        {"admin", ("admin", "Admin", true) },
        {"user", ("user", "User", false) },
        {"manager", ("manager", "Manager", false) },
        {"user1", ("user1", "User", false) },
        {"user2", ("user2", "User", false) }
    };

    public AuthController(ILogger<AuthController> logger)
    {
        _logger = logger;
    }

    [HttpPost("Login")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult Login(LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new LoginResponse
            {
                Success = false,
                Message = "Invalid request."
            });
        }

        if (!Users.TryGetValue(request.Username, out var userInfo) || userInfo.Password != request.Password)
        {
            _logger.LogInformation($"Failed login attempt for username: {request.Username}");
            return Unauthorized(new LoginResponse
            {
                Success = false,
                Message = "Invalid username or password."
            });
        }

        var authenticatedUser = new AuthenticatedUser
        {
            UserId = Guid.NewGuid().ToString(),
            Username = request.Username,
            Role = userInfo.Role,
            IsAdmin = userInfo.IsAdmin,
            LoginTime = DateTime.UtcNow
        };
        
        string userJson = JsonSerializer.Serialize(authenticatedUser);

        Response.Cookies.Append(AUTH_COOKIE_NAME, userJson, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTimeOffset.UtcNow.AddHours(2)
        });

        _logger.LogInformation($"User {request.Username} logged in successfully with role {userInfo.Role}");

        return Ok(new LoginResponse
        {
            Success = true,
            Message = "Login Successful",
            User = authenticatedUser
        });
    }

    [HttpPost("Logout")]
    public IActionResult Logout()
    {
        var user = HttpContext.Items["AuthenticatedUser"] as AuthenticatedUser;

        if(user != null)
        {
            _logger.LogInformation($"User {user.Username} logged out.");
        }

        Response.Cookies.Delete(AUTH_COOKIE_NAME);

        return Ok(new
        {
            Success = true,
            Message = "Logged out Successfully."
        });
    }

    [HttpGet("me")]
    [RequireAuthentication]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult GetLoggedInUser()
    {
        var user = HttpContext.Items["AuthenticatedUser"] as AuthenticatedUser;

        return Ok(new
        {
            Success = true,
            User = user
        });
    }


    [HttpGet("test-auth")]
    [RequireAuthentication]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult TestAuthentication()
    {
        var user = HttpContext.Items["AuthenticatedUser"] as AuthenticatedUser;

        return Ok(new
        {
            Message = "You are Authenticated",
            User = user
        });
    }


    [HttpGet("test-admin")]
    [RequiresAdmin]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult TestAdmin()
    {
        var user = HttpContext.Items["AuthenticatedUser"] as AuthenticatedUser;

        return Ok(new
        {
            Message = "You have admin role.",
            User = user
        });
    }


    [HttpGet("test-role")]
    [RequireRole("Manager, Role")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult TestRole()
    {
        var user = HttpContext.Items["AuthenticatedUser"] as AuthenticatedUser;

        return Ok(new
        {
            Message = "You have required role.",
            User = user
        });
    }


    [HttpGet("demo-user")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult GetDemoUsers()
    {
        var demoUsers = Users.Select(u => new
        {
            Username = u.Key,
            Password = u.Value.Password,
            Role = u.Value.Role
        });

        return Ok(new
        {
            Message = "Demo users for testing",
            DemoUsers = demoUsers
        });
    }
}
