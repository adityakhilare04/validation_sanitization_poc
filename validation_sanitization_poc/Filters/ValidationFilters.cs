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
