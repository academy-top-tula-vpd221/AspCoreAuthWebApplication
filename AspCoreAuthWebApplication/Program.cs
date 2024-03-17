using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

List<User> users = new()
{
    new(){ Login = "bobby", Password = "qwerty" },
    new(){ Login = "tommy", Password = "12345" },
};

var builder = WebApplication.CreateBuilder();
builder.Services.AddAuthorization();
builder.Services
       .AddAuthentication("Bearer")
       .AddJwtBearer(options =>
       {
           options.TokenValidationParameters = new()
           {
               ValidateIssuer = true,
               ValidIssuer = AuthOptions.Issuer,

               ValidateAudience = true,
               ValidAudience = AuthOptions.Client,

               IssuerSigningKey = AuthOptions.SecurityKey(),
               ValidateIssuerSigningKey = true,

               ValidateLifetime = true,
           };
       });


var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello World!");
app.Map("/admin", [Authorize]() => "Admin page");
app.Map("/login", (User userData) =>
{
    User? user = users.FirstOrDefault(u => u.Login == userData.Login);

    if (user is null) return Results.Unauthorized();

    var claims = new List<Claim> { new(ClaimTypes.Name, user.Login) };

    var token = new JwtSecurityToken(
        issuer: AuthOptions.Issuer,
        audience: AuthOptions.Client,
        claims: claims,
        expires: DateTime.Now.Add(TimeSpan.FromSeconds(60)),
        signingCredentials: new SigningCredentials(AuthOptions.SecurityKey(), SecurityAlgorithms.HmacSha256)
        );

    var tokenHandler = new JwtSecurityTokenHandler().WriteToken(token);

    var tokenResponse = new
    {
        handler = tokenHandler,
        login = user.Login
    };

    return Results.Json(tokenHandler);
});

app.Run();


class AuthOptions
{
    public static string Issuer { get; } = "Server";
    public static string Client { get; } = "Client";
    const string Key = "LHp8k1l4B2Ja0YtKCEc0MJsCjFfnFzDfkn9eT57GSj9rz0Q7IwsvXM24OtXoCx91OjXpHcDtwo592GGZSwL11HzCoE5fGFO42QOE";
    public static SymmetricSecurityKey SecurityKey() => new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Key));
}


class User
{
    public string Login { get; set; } = "";
    public string Password { get; set; } = "";
}