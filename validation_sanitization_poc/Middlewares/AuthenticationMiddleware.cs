using System.Text.Json;
using validation_sanitization_poc.Models;

namespace validation_sanitization_poc.Middlewares;

public class CookieAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<CookieAuthenticationMiddleware> _logger;
    private const string AUTH_COOKIE_NAME = "AuthToken";

    public CookieAuthenticationMiddleware(RequestDelegate next, ILogger<CookieAuthenticationMiddleware> logger)
    {
        _logger = logger;
        _next = next;
    }

    public async Task InvokeAsync(HttpContext httpContext)
    {
        //Skip authentication for public endpoints
        var path = httpContext.Request.Path.Value?.ToLower() ?? "";

        if (path.StartsWith("/swagger") ||
            path.StartsWith("/_framework") ||
            path == "/api/auth/login" ||
            path == "/api/auth/logout" ||
            path == "/health" ||
            path == "/" ||
            path == "/api/auth/demo-user")
        {
            await _next(httpContext);
            return;
        }

        if (httpContext.Request.Cookies.TryGetValue(AUTH_COOKIE_NAME, out var authToken))
        {
            try
            {
                //Deserialize user from cookie
                var user = JsonSerializer.Deserialize<AuthenticatedUser>(authToken);

                if (user != null)
                {
                    httpContext.Items["AuthenticatedUser"] = user;
                    _logger.LogInformation($"User {user.Username} is authenticated via cookies.");

                    await _next(httpContext);
                    return;
                }
                else
                {
                    _logger.LogWarning("Authenticated cookie deserialized to null user.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to deserialize the cookie");               
            }
        }

        //No valid authentication found - return 401 unauthorized
        _logger.LogWarning($"Unauthorized access attempt to protected endpoint: {path}");

        httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
        httpContext.Response.ContentType = "application/json";

        var response = new
        {
            Message = "Authenticated required.",
            Error = "You must be logged in to access this resource.",
            LoginEndpoint = "/api/auth/login",
            Path = path
        };

        await httpContext.Response.WriteAsJsonAsync(response);
    }
}

public static class CookieAuthenticationMiddlewareExtensions
{
    public static IApplicationBuilder UseCookieAuthentication(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<CookieAuthenticationMiddleware>();
    }
}
