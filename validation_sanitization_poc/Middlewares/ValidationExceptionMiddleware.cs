using Microsoft.AspNetCore.Http;
using System.Text.Json;
namespace validation_sanitization_poc.Middlewares;

public class ValidationExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ValidationExceptionMiddleware> _logger;

    public ValidationExceptionMiddleware(RequestDelegate next, ILogger<ValidationExceptionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (ValidationException ex)
        {
            _logger.LogError(ex, "Validation error occured.");
            await HandleValidationExceptionAsync(context, ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Something went wrong during your request.");
            await HandleExceptionAsync(context, ex);
        }
    }

    private async Task HandleValidationExceptionAsync(HttpContext httpContext, ValidationException ex)
    {
        httpContext.Response.ContentType = "application/json";
        httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;

        var response = new
        {
            StatusCodes = httpContext.Response.StatusCode,
            Message = "Validation Error",
            Errors = ex.Errors
        };

        await httpContext.Response.WriteAsJsonAsync(JsonSerializer.Serialize(response));
    }

    private async Task HandleExceptionAsync(HttpContext httpContext, Exception ex)
    {
        httpContext.Response.ContentType = "application/json";
        httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;

        var response = new
        {
            StatusCodes = httpContext.Response.StatusCode,
            Message = "Internal Server Error",
            Errors = ex.Message
        };

        await httpContext.Response.WriteAsJsonAsync(response);

    }
}

public class ValidationException : Exception
{
    public Dictionary<string, string[]> Errors { get; set; }

    public ValidationException(Dictionary<string, string[]> errors)
        : base("One or more validation error occured.")
    {
        Errors = errors;
    }

    public ValidationException(string key, string error)
        : base ("One or more validation error occured.")
    {
        Errors = new Dictionary<string, string[]>
        {
            {key, new[] { error } }
        };
    }
}

public class RequestSanitizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestSanitizationMiddleware> _logger;

    public RequestSanitizationMiddleware(RequestDelegate next, ILogger<RequestSanitizationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async void InvokeAsync(HttpContext httpContext)
    {
        if (httpContext.Request.Path.StartsWithSegments("/swagger") ||
            httpContext.Request.Path.StartsWithSegments("/_fragment"))
        {
            await _next(httpContext);
            return;
        }

        if (httpContext.Request.Query.Any())
        {
            _logger.LogInformation("Sanitizing query parameter.");
        }

        var skipHeaders = new[]
        {
            "Host", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language", "Connection", "Referer",
            "sec-", "cache-control", "pragma", "Content-Type", "Content-Length", "Cookie", "Authorization", "X-",
            "Api-", "Client-"
        };

        foreach (var header in httpContext.Request.Headers)
        {
            if (skipHeaders.Any(x => header.Key.StartsWith(x, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (ContainMaliciousContent(header.Value.ToString()))
            {
                _logger.LogWarning($"Malicious content detected in header: {header.Key}");
                httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
                await httpContext.Response.WriteAsync("Malicious content detected in request.");
                return;
            }
        }

        await _next(httpContext);
    }

    private bool ContainMaliciousContent (string content)
    {
        if (string.IsNullOrEmpty(content))
            return false;

        var maliciousPatterns = new[]
        {
            "<script",
            "javascript:",
            "onerror=",
            "onclick=",
            "onload=",
            "<iframe",
            "eval(",
            "expression("
        };

        return maliciousPatterns.Any(x => content.Contains(x, StringComparison.OrdinalIgnoreCase));
    }
}

public class RequestValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestValidationMiddleware> _logger;
    private const long MaxRequestBodySize = 10 * 1024 * 1024; // 10MB

    public RequestValidationMiddleware(RequestDelegate next, ILogger<RequestValidationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync (HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments("/swagger") ||
            context.Request.Path.StartsWithSegments("/_fragment"))
        {
            await _next(context);
            return;
        }

        if (context.Request.ContentLength.HasValue && context.Request.ContentLength > MaxRequestBodySize)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            context.Response.ContentType = "application/json";

            var response = new
            {
                StatusCode = context.Response.StatusCode,
                Message = "Request Body too large",
                MaxAllowedSize = $"{MaxRequestBodySize / 1024 / 1024} MB",
                ActualSize = $"{context.Request.ContentLength / 1024 / 1024}"
            };

            await context.Response.WriteAsJsonAsync(response);
            return;
        }

        await _next(context);
    }
}
