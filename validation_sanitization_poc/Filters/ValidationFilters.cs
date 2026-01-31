using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using validation_sanitization_poc.Models;

namespace validation_sanitization_poc.Filters;

public class RequireAuthenticationAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        var user = context.HttpContext.Items["AuthenticatedUser"] as AuthenticatedUser;

        if (user == null)
        {
            context.Result = new ObjectResult(new
            {
                Message = "Authentication Required",
                Error = "You must be logged in be logged in to access this resource",
                LoginEndpoint = "/api/auth/login"
            })
            { 
                StatusCode = StatusCodes.Status401Unauthorized
            };
            return;
        }
        
        base.OnActionExecuting(context);
    }
}

public class RequiresAdminAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        var user = context.HttpContext.Items["AuthenticatedUser"] as AuthenticatedUser;

        if (user == null)
        {
            context.Result = new ObjectResult(new
            {
                Message = "Authentication Required",
                Error = "You must be logged in be logged in to access this resource",
                LoginEndpoint = "/api/auth/login"
            })
            {
                StatusCode = StatusCodes.Status401Unauthorized
            };
            return;
        }

        if (!user.IsAdmin)
        {
            context.Result = new ObjectResult(new
            {
                Message = "Admin Access Required",
                Error = "You must have Admin role to access this resource",
                YourRole = user.Role
            })
            {
                StatusCode = StatusCodes.Status403Forbidden
            };
            return;
        }

        base.OnActionExecuting(context);
    }
}

public class RequireRoleAttribute : ActionFilterAttribute
{
    private readonly string[] _roles;
    public RequireRoleAttribute(params string[] roles)
    {
        _roles = roles;
    }
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        var user = context.HttpContext.Items["AuthenticatedUser"] as AuthenticatedUser;

        if (user == null)
        {
            context.Result = new ObjectResult(new
            {
                Message = "Authentication Required",
                Error = "You must be logged in be logged in to access this resource"
            })
            {
                StatusCode = StatusCodes.Status401Unauthorized
            };
            return;
        }

        if (!_roles.Contains(user.Role, StringComparer.OrdinalIgnoreCase))
        {
            context.Result = new ObjectResult(new
            {
                Message = "Forbidden",
                RequiredRoles = _roles,
                YourRole = user.Role,
                Error = "You do not have required role to access this resouce."
            })
            {
                StatusCode = StatusCodes.Status403Forbidden
            };
            return;
        }

        base.OnActionExecuting(context);
    }
}



public class RequireApiKeyAttribute : ActionFilterAttribute
{
    private const string API_KEY_HEADER = "X-API-Key";
    private static readonly string[] VALID_API_KEYS = { "demo-key-123", "test-key-999", "admin-key-123" };

    public override void OnActionExecuted(ActionExecutedContext context)
    {
        if (!context.HttpContext.Request.Headers.TryGetValue(API_KEY_HEADER, out var apiKey))
        {
            context.Result = new ObjectResult(new
            {
                Message = "API Key Required",
                Error = $"Missing {API_KEY_HEADER} header"
            })
            {
                StatusCode = StatusCodes.Status401Unauthorized
            };
            return;
        }

        if (!VALID_API_KEYS.Contains(apiKey.ToString(), StringComparer.OrdinalIgnoreCase))
        {
            context.Result = new ObjectResult(new
            {
                Message = "Invalid API Key",
                Error = "Provided API Key is not valid."
            })
            {
                StatusCode = StatusCodes.Status401Unauthorized
            };
            return;
        }

        base.OnActionExecuted(context);
    }
}
