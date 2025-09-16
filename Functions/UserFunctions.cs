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

    // DTOs
    public class UserDto
    {
        public int UserID { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? PhoneNo { get; set; }
        public string? Password { get; set; } // Only for create/update
        public int UserType { get; set; }
        public long? FingerprintNum { get; set; }
        public bool? FingerprintEnabled { get; set; }
        public bool? UserEnabled { get; set; }
    }

    public class CreateUserDto
    {
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? PhoneNo { get; set; }
        public string Password { get; set; } = string.Empty;
        public int UserType { get; set; }
        public bool? FingerprintEnabled { get; set; }
        public bool? UserEnabled { get; set; }
    }

    public class UpdateUserDto
    {
        public int UserID { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? PhoneNo { get; set; }
        public string? Password { get; set; } // Optional for updates
        public int UserType { get; set; }
        public bool? FingerprintEnabled { get; set; }
        public bool? UserEnabled { get; set; }
    }

    // Azure Functions
    [Function("GetUsers")]
    public async Task<IActionResult> GetUsers(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "users")] HttpRequest req)
    {
        try
        {
            using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
            await conn.OpenAsync();

            var cmd = new SqlCommand(@"
            SELECT UserID, UserName, Email, PhoneNo, UserType, 
                   FingerprintNum, FingerprintEnabled, UserEnabled 
            FROM dbo.Users 
            ORDER BY UserName", conn);

            var users = new List<UserDto>();
            using var reader = await cmd.ExecuteReaderAsync();

            while (await reader.ReadAsync())
            {
                users.Add(new UserDto
                {
                    UserID = ReadInt32(reader, "UserID"),
                    UserName = ReadString(reader, "UserName"),
                    Email = ReadString(reader, "Email"),
                    PhoneNo = ReadString(reader, "PhoneNo"),
                    UserType = ReadInt32(reader, "UserType"),
                    FingerprintNum = ReadInt64(reader, "FingerprintNum"),
                    FingerprintEnabled = ReadBit(reader, "FingerprintEnabled"),
                    UserEnabled = ReadBit(reader, "UserEnabled")
                });
            }

            return new OkObjectResult(users);
        }
        catch (Exception ex)
        {
            return new BadRequestObjectResult($"Error: {ex.Message}");
        }
    }

    // move these to utility class
    private static int ReadInt32(SqlDataReader reader, string fieldName)
    {
        return reader.IsDBNull(reader.GetOrdinal(fieldName)) ? 0 : Convert.ToInt32(reader.GetValue(reader.GetOrdinal(fieldName)));
    }

    private static long ReadInt64(SqlDataReader reader, string fieldName)
    {
        return reader.IsDBNull(reader.GetOrdinal(fieldName)) ? 0 : Convert.ToInt64(reader.GetValue(reader.GetOrdinal(fieldName)));
    }

    private static bool ReadBit(SqlDataReader reader, string fieldName)
    {
        return reader.IsDBNull(reader.GetOrdinal(fieldName)) ? false : Convert.ToBoolean(reader.GetValue(reader.GetOrdinal(fieldName)));
    }

    private static string ReadString(SqlDataReader reader, string fieldName)
    {
        return reader.IsDBNull(reader.GetOrdinal(fieldName)) ? "" : Convert.ToString(reader.GetValue(reader.GetOrdinal(fieldName)));
    }

    [Function("GetUser")]
    public async Task<IActionResult> GetUser(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "users/{id:int}")] HttpRequest req,
        int id)
    {
        try
        {
            using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
            await conn.OpenAsync();

            var cmd = new SqlCommand(@"
            SELECT UserID, UserName, Email, PhoneNo, UserType, 
                   FingerprintNum, FingerprintEnabled, UserEnabled 
            FROM dbo.Users 
            WHERE UserID = @UserID", conn);

            cmd.Parameters.AddWithValue("@UserID", id);

            using var reader = await cmd.ExecuteReaderAsync();

            if (await reader.ReadAsync())
            {
                var user = new UserDto
                {
                    UserID = ReadInt32(reader, "UserID"),
                    UserName = ReadString(reader, "UserName"),
                    Email = ReadString(reader, "Email"),
                    PhoneNo = ReadString(reader, "PhoneNo"),
                    UserType = ReadInt32(reader, "UserType"),
                    FingerprintNum = ReadInt64(reader, "FingerprintNum"),
                    FingerprintEnabled = ReadBit(reader, "FingerprintEnabled"),
                    UserEnabled = ReadBit(reader, "UserEnabled")
                };

                return new OkObjectResult(user);
            }

            return new NotFoundObjectResult("User not found");
        }
        catch (Exception ex)
        {
            return new BadRequestObjectResult($"Error: {ex.Message}");
        }
    }

    [Function("CreateUser")]
    public async Task<IActionResult> CreateUser(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "users")] HttpRequest req)
    {
        try
        {
            var body = await new StreamReader(req.Body).ReadToEndAsync();
            var dto = JsonSerializer.Deserialize<CreateUserDto>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (dto == null || string.IsNullOrWhiteSpace(dto.UserName) ||
                string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Password))
            {
                return new BadRequestObjectResult("UserName, Email, and Password are required");
            }

            using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
            await conn.OpenAsync();

            // Check if email already exists
            var checkCmd = new SqlCommand("SELECT COUNT(*) FROM dbo.Users WHERE Email = @Email", conn);
            checkCmd.Parameters.AddWithValue("@Email", dto.Email);
            var exists = (int)await checkCmd.ExecuteScalarAsync() > 0;

            if (exists)
            {
                return new BadRequestObjectResult("Email already exists");
            }

            var cmd = new SqlCommand(@"
            INSERT INTO dbo.Users (UserName, Email, PhoneNo, Password, UserType, FingerprintEnabled, UserEnabled)
            OUTPUT INSERTED.UserID
            VALUES (@UserName, @Email, @PhoneNo, @Password, @UserType, @FingerprintEnabled, @UserEnabled)", conn);

            cmd.Parameters.AddWithValue("@UserName", dto.UserName);
            cmd.Parameters.AddWithValue("@Email", dto.Email);
            cmd.Parameters.AddWithValue("@PhoneNo", (object?)dto.PhoneNo ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@Password", dto.Password); // Assume password is already hashed from client
            cmd.Parameters.AddWithValue("@UserType", dto.UserType);
            cmd.Parameters.AddWithValue("@FingerprintEnabled", (object?)dto.FingerprintEnabled ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@UserEnabled", (object?)dto.UserEnabled ?? DBNull.Value);

            var newUserId = (int)await cmd.ExecuteScalarAsync();

            return new OkObjectResult(new { UserID = newUserId, Message = "User created successfully" });
        }
        catch (Exception ex)
        {
            return new BadRequestObjectResult($"Error: {ex.Message}");
        }
    }

    [Function("UpdateUser")]
    public async Task<IActionResult> UpdateUser(
        [HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "users/{id:int}")] HttpRequest req,
        int id)
    {
        try
        {
            var body = await new StreamReader(req.Body).ReadToEndAsync();
            var dto = JsonSerializer.Deserialize<UpdateUserDto>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (dto == null || string.IsNullOrWhiteSpace(dto.UserName) || string.IsNullOrWhiteSpace(dto.Email))
            {
                return new BadRequestObjectResult("UserName and Email are required");
            }

            using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
            await conn.OpenAsync();

            // Check if email already exists for other users
            var checkCmd = new SqlCommand("SELECT COUNT(*) FROM dbo.Users WHERE Email = @Email AND UserID != @UserID", conn);
            checkCmd.Parameters.AddWithValue("@Email", dto.Email);
            checkCmd.Parameters.AddWithValue("@UserID", id);
            var exists = (int)await checkCmd.ExecuteScalarAsync() > 0;

            if (exists)
            {
                return new BadRequestObjectResult("Email already exists for another user");
            }

            // Build dynamic update query based on provided fields
            var updateFields = new List<string>
        {
            "UserName = @UserName",
            "Email = @Email",
            "PhoneNo = @PhoneNo",
            "UserType = @UserType",
            "FingerprintEnabled = @FingerprintEnabled",
            "UserEnabled = @UserEnabled"
        };

            if (!string.IsNullOrWhiteSpace(dto.Password))
            {
                updateFields.Add("Password = @Password");
            }

            var sql = $@"
            UPDATE dbo.Users 
            SET {string.Join(", ", updateFields)}
            WHERE UserID = @UserID";

            var cmd = new SqlCommand(sql, conn);

            cmd.Parameters.AddWithValue("@UserID", id);
            cmd.Parameters.AddWithValue("@UserName", dto.UserName);
            cmd.Parameters.AddWithValue("@Email", dto.Email);
            cmd.Parameters.AddWithValue("@PhoneNo", (object?)dto.PhoneNo ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@UserType", dto.UserType);
            cmd.Parameters.AddWithValue("@FingerprintEnabled", (object?)dto.FingerprintEnabled ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@UserEnabled", (object?)dto.UserEnabled ?? DBNull.Value);

            if (!string.IsNullOrWhiteSpace(dto.Password))
            {
                cmd.Parameters.AddWithValue("@Password", dto.Password); // Assume password is already hashed from client
            }

            var rowsAffected = await cmd.ExecuteNonQueryAsync();

            if (rowsAffected == 0)
            {
                return new NotFoundObjectResult("User not found");
            }

            return new OkObjectResult(new { Message = "User updated successfully" });
        }
        catch (Exception ex)
        {
            return new BadRequestObjectResult($"Error: {ex.Message}");
        }
    }

    [Function("CheckFingerprintStatus")]
    public async Task<IActionResult> CheckFingerprintStatus(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "users/{id:int}/fingerprint-status")] HttpRequest req,
        int id)
    {
        try
        {
            using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
            await conn.OpenAsync();

            var cmd = new SqlCommand("SELECT FingerprintNum FROM dbo.Users WHERE UserID = @UserID", conn);
            cmd.Parameters.AddWithValue("@UserID", id);

            var result = await cmd.ExecuteScalarAsync();
            var fingerprintNum = result == DBNull.Value ? null : (long?)result;

            return new OkObjectResult(new { FingerprintNum = fingerprintNum });
        }
        catch (Exception ex)
        {
            return new BadRequestObjectResult($"Error: {ex.Message}");
        }
    }
    
     
}