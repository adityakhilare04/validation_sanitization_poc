using validation_sanitization_poc.Filters;
using validation_sanitization_poc.Middlewares;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

//Register Authorization Filters
builder.Services.AddScoped<RequireAuthenticationAttribute>();
builder.Services.AddScoped<RequiresAdminAttribute>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Middlewares
app.UseMiddleware<RequestValidationMiddleware>();
app.UseMiddleware<RequestSanitizationMiddleware>();
app.UseCookieAuthentication();
app.UseMiddleware<ValidationExceptionMiddleware>();

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
