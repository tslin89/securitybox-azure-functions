using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
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
using SecurityBoxFunctions.Library;
using Microsoft.Azure.SignalR.Management;
using System.Text.Json.Serialization;
using Microsoft.Azure.SignalR.Management;
using System.Text.Json.Serialization;
using Microsoft.Azure.Functions.Worker.Extensions.SignalRService;
using Microsoft.AspNetCore.Http.HttpResults;


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
            string passwordFromDb;
            Users user;

            await using (var conn = new SqlConnection(cs))
            {
                await conn.OpenAsync();

                // todo: inclue password hash in query
                var cmd = new SqlCommand(
                    @"SELECT UserID, UserName, Email, Password, PhoneNo
                      FROM Users 
                      WHERE Email = @Email", conn);

                cmd.Parameters.AddWithValue("@Email", login.Email);

                await using var reader = await cmd.ExecuteReaderAsync();
                if (!await reader.ReadAsync())
                {
                    return new UnauthorizedObjectResult(new ResponseObject
                    {
                        Status = -1,
                        Message = "User not found for " + login.Email
                    });
                }

                string passwordFromDB = reader.GetString(reader.GetOrdinal("Password"));

                if (login.Password != passwordFromDB)
                {
                    return new UnauthorizedObjectResult(new ResponseObject
                    {
                        Status = -1,
                        Message = "Your password is incorrect."
                    });
                }

                user = new Users
                {
                    UserID = reader.GetInt32(reader.GetOrdinal("UserID")),
                    UserName = reader.GetString(reader.GetOrdinal("UserName")),
                    Email = reader.GetString(reader.GetOrdinal("Email")),
                    PhoneNo = reader.GetString(reader.GetOrdinal("PhoneNo"))
                };

                // I will not use server side hashing for this project as the focus is not on web app security. encrypted value will be directly compared.
                // passwordHash = BCrypt.Net.BCrypt.HashPassword($"{userId}{emailFromDb}");
            }

            //bool ok = BCrypt.Net.BCrypt.Verify(login.Password, passwordHash);
            //if (!ok)
            //    return new UnauthorizedObjectResult(new { error = "Invalid credentials" });

            // initiate SignalR connection info
            //var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
            //response.WriteAsJsonAsync(connectionInfo);
            

            ResponseObject responseObj = null;

            //var signalR = await GetSignalRInfoAsync("alerts", user.UserID.ToString());

            string token = Utilities.GenerateJWTToken(user.Email,
                _configuration["Jwt:Key"],
                _configuration["Jwt:Issuer"],
                _configuration["Jwt:Audience"]);

            responseObj = new ResponseObject();
            responseObj.Data = new
            {
                Token = token,
                User = user
            };

            return new OkObjectResult(responseObj);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "UserLogin failed");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }

    [Function("negotiateSignalR")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequestData req,
        [SignalRConnectionInfoInput(HubName = "alerts", ConnectionStringSetting = "AzureSignalRConnectionString")] SignalRConnectionInfo connectionInfo)
    {
        ResponseObject responseObj = new ResponseObject();
        responseObj.Data = connectionInfo;

        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        await response.WriteAsJsonAsync(responseObj);

        return response;
    }

    [GeneratedRegex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
    private static partial Regex EmailRegex();
}