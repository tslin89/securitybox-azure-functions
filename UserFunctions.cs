using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Data.SqlClient;
using SecurityBoxFunctions.Model.Entities;
using System.Text.RegularExpressions;
using System.Text.Json;
using BCrypt.Net;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace Winter.SecurityBox;

public partial class UserFunctions
{
    private readonly ILogger<UserFunctions> _logger;
    private readonly IConfiguration _configuration;

    public UserFunctions(ILogger<UserFunctions> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    [Function("UserLogin")]
    public async Task<IActionResult> UserLogin(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "auth/login")] HttpRequest req)
    {
        try
        {
            // 1) Read JSON body
            var body = await new StreamReader(req.Body).ReadToEndAsync();
            var login = JsonSerializer.Deserialize<LoginRequest>(body, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (login is null || string.IsNullOrWhiteSpace(login.Email) || string.IsNullOrWhiteSpace(login.Password))
                return new BadRequestObjectResult(new { error = "Email and password are required" });

            if (!EmailRegex().IsMatch(login.Email))
                return new BadRequestObjectResult(new ResponseObject
                {
                    Status = -1,
                    Message = "Invalid email format"
                });

            // 2) Look up user
            string cs = _configuration["SqlConnectionString"];
            int userId;
            string emailFromDb;
            string passwordHash;

            await using (var conn = new SqlConnection(cs))
            {
                await conn.OpenAsync();

                // todo: inclue password hash in query
                var cmd = new SqlCommand(
                    @"SELECT UserID, UserName, Email
                      FROM Users 
                      WHERE Email = @Email", conn);

                cmd.Parameters.AddWithValue("@Email", login.Email);
                cmd.Parameters.AddWithValue("@PasswordHash", BCrypt.Net.BCrypt.HashPassword(login.Password));

                await using var reader = await cmd.ExecuteReaderAsync();
                if (!await reader.ReadAsync())
                {
                    return new UnauthorizedObjectResult(new ResponseObject
                    {
                        Status = -1,
                        Message = "Invalid credentials for user " + login.Email
                    });
                }

                userId = reader.GetInt32(reader.GetOrdinal("UserID"));
                emailFromDb = reader.GetString(reader.GetOrdinal("Email"));
                //passwordHash = reader.GetString(reader.GetOrdinal("PasswordHash"));

                // Temporary: since we don't yet have passwords in the DB
                passwordHash = BCrypt.Net.BCrypt.HashPassword($"{userId}{emailFromDb}");

            }

            //bool ok = BCrypt.Net.BCrypt.Verify(login.Password, passwordHash);
            //if (!ok)
            //    return new UnauthorizedObjectResult(new { error = "Invalid credentials" });

            // 4) Issue JWT
            // var token = CreateJwt(
            //     userId,
            //     emailFromDb,
            //     _configuration["Jwt:Key"],       // a long random secret
            //     _configuration["Jwt:Issuer"],    // e.g. https://yourdomain
            //     _configuration["Jwt:Audience"]   // e.g. your frontend origin
            // );

            ResponseObject responseObj = new ResponseObject();
            responseObj.Data = new
            {
                Token = passwordHash, //token, // change here later
                User = new { id = userId, email = emailFromDb }
            };

            return new OkObjectResult(responseObj);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "UserLogin failed");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }

    // Minimal JWT creator
    private static string CreateJwt(int userId, string email, string? key, string? issuer, string? audience)
    {
        if (string.IsNullOrWhiteSpace(key))
            throw new InvalidOperationException("JWT key not configured");

        var creds = new SigningCredentials(
            new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(key)),
            SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var jwt = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    [GeneratedRegex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
    private static partial Regex EmailRegex();
}