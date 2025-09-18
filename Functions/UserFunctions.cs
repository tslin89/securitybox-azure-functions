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
using System.Data;
using Org.BouncyCastle.Asn1.Ocsp;


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
            List<BoxDto> boxes = new();
            List<EventCodeDto> eventCodes = new();

            await using (var conn = new SqlConnection(cs))
            {
                await conn.OpenAsync();

                var sql = @"
                -- 1) user
                SELECT TOP (1) UserID, UserName, Email, Password, PhoneNo, BoxID
                FROM Users WHERE Email = @Email;

                -- 2) boxes
                SELECT BoxID, DeviceID, Description
                FROM dbo.Boxes WHERE IsEnabled = 1;

                -- 3) event codes
                SELECT EventCode, EventDescription, EventType
                FROM dbo.EventCodes;";

                await using var cmd = new SqlCommand(sql, conn);
                cmd.Parameters.AddWithValue("@Email", login.Email);

                await using var r = await cmd.ExecuteReaderAsync();

                // user
                if (!await r.ReadAsync())
                    return new OkObjectResult(new ResponseObject
                    {
                        Status = (int)CommonEnum.ResponseStatus.Failed,
                        Message = "User not registered."
                    });

                var passwordFromDB = r.GetString(r.GetOrdinal("Password"));
                if (login.Password != passwordFromDB)
                    return new OkObjectResult(new ResponseObject
                    {
                        Status = (int)CommonEnum.ResponseStatus.Failed,
                        Message = "Failed to Login. Please check your credentials."
                    });

                user = new Users
                {
                    UserID = r.GetInt32(r.GetOrdinal("UserID")),
                    UserName = r.GetString(r.GetOrdinal("UserName")),
                    Email = r.GetString(r.GetOrdinal("Email")),
                    PhoneNo = r.IsDBNull(r.GetOrdinal("PhoneNo")) ? "" : r.GetString(r.GetOrdinal("PhoneNo")),
                    BoxID = ReadInt64(r, "BoxID")
                };

                // boxes
                await r.NextResultAsync();
                while (await r.ReadAsync())
                {
                    boxes.Add(new BoxDto(
                        BoxID: r.GetInt64(r.GetOrdinal("BoxID")),
                        DeviceID: r.IsDBNull(r.GetOrdinal("DeviceID")) ? "" : r.GetString(r.GetOrdinal("DeviceID")),
                        Description: r.IsDBNull(r.GetOrdinal("Description")) ? "" : r.GetString(r.GetOrdinal("Description"))
                    ));
                }

                // event codes
                await r.NextResultAsync();
                while (await r.ReadAsync())
                {
                    eventCodes.Add(new EventCodeDto(
                        EventCode: r.GetString(r.GetOrdinal("EventCode")),
                        EventDescription: r.IsDBNull(r.GetOrdinal("EventDescription")) ? "" : r.GetString(r.GetOrdinal("EventDescription")),
                        EventType: ReadInt32(r, "EventType")
                    ));
                }
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
                User = user,
                BoxList = boxes,       // your (1)
                EventCodes = eventCodes // your (2)
            };

            return new OkObjectResult(responseObj);
        }
        catch (SqlException ex) when (ex.Number == 40613 || ex.Number == -2)
        {
            _logger.LogError(ex, "UserLogin failed by inactive database");
            return new OkObjectResult(new ResponseObject
            {
                Status = (int)CommonEnum.ResponseStatus.Failed,
                Message = "Unable to login at this moment. Please try again in 10-30 seconds."
            });
        }
        catch (SqlException ex)
        {
            _logger.LogError(ex, "UserLogin failed by database error");
            return new OkObjectResult(new ResponseObject
            {
                Status = (int)CommonEnum.ResponseStatus.Failed,
                Message = "System is not available. Please contact system administrators."
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "UserLogin failed");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }

    public record BoxDto(long BoxID, string DeviceID, string Description);
    public record EventCodeDto(string EventCode, string EventDescription, int EventType);

    [Function("negotiateSignalR")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequestData req,
        [SignalRConnectionInfoInput(
            HubName = "alerts",
            ConnectionStringSetting = "AzureSignalRConnectionString",
            UserId = "{query.userId}")] SignalRConnectionInfo connectionInfo)
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
        public long? BoxID { get; set; }
        public bool IsEnabled { get; set; }
    }

    public class CreateUserDto
    {
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? PhoneNo { get; set; }
        public string Password { get; set; } = string.Empty;
        public int UserType { get; set; }
        public bool? FingerprintEnabled { get; set; }
        public long BoxID { get; set; }
        public bool IsEnabled { get; set; }
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
        public long BoxID { get; set; }
        public bool IsEnabled { get; set; }
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
                   FingerprintNum, FingerprintEnabled, BoxID, IsEnabled
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
                    BoxID = ReadInt64(reader, "BoxID"),
                    IsEnabled = ReadBit(reader, "IsEnabled"),
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
                   FingerprintNum, FingerprintEnabled, BoxID, IsEnabled
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
                    BoxID = ReadInt64(reader, "BoxID"),
                    IsEnabled = ReadBit(reader, "IsEnabled"),
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
            INSERT INTO dbo.Users (UserName, Email, PhoneNo, Password, UserType, FingerprintEnabled, IsEnabled, BoxID)
            OUTPUT INSERTED.UserID
            VALUES (@UserName, @Email, @PhoneNo, @Password, @UserType, @FingerprintEnabled, @IsEnabled, @BoxID)", conn);

            cmd.Parameters.AddWithValue("@UserName", dto.UserName);
            cmd.Parameters.AddWithValue("@Email", dto.Email);
            cmd.Parameters.AddWithValue("@PhoneNo", (object?)dto.PhoneNo ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@Password", dto.Password); // Assume password is already hashed from client
            cmd.Parameters.AddWithValue("@UserType", dto.UserType);
            cmd.Parameters.AddWithValue("@FingerprintEnabled", (object?)dto.FingerprintEnabled ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@IsEnabled", (object?)dto.IsEnabled ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@BoxID", (object?)dto.BoxID ?? DBNull.Value);

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
            var checkCmd = new SqlCommand("SELECT COUNT(1) FROM dbo.Users WHERE Email = @Email AND UserID != @UserID", conn);
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
            "IsEnabled = @IsEnabled"
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
            cmd.Parameters.AddWithValue("@IsEnabled", (object?)dto.IsEnabled ?? DBNull.Value);

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

    [Function("DeleteUser")]
    public async Task<IActionResult> DeleteUser(
        [HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "users/{id:int}")] HttpRequest req,
        int id)
    {
        try
        {
            using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
            await conn.OpenAsync();

            var sql = $@"
            DELETE FROM dbo.Users 
            WHERE UserID = @UserID";

            var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@UserID", id);

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

    [Function("GetUserEventSettings")]
    public async Task<IActionResult> GetUserEventSettings(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "users/{id:int}/eventsettings")] HttpRequest req,
        int id)
    {
        try
        {
            using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
            await conn.OpenAsync();

            var cmd = new SqlCommand(@"
                SELECT c.EventCode, c.EventDescription, c.EventType, COALESCE(u.NotificationEnabled, 1) AS NotificationEnabled
                FROM EventCodes as c
                LEFT JOIN UserEventSettings as u ON u.EventCode = c.EventCode AND u.UserID = @UserID
                WHERE c.IsC2D = 0", conn);
            cmd.Parameters.AddWithValue("@UserID", id);

            using var reader = await cmd.ExecuteReaderAsync();

            List<UserEventSettings> result = new List<UserEventSettings>();
            while (await reader.ReadAsync())
            {
                result.Add(new UserEventSettings
                {
                    EventCode = ReadString(reader, "EventCode"),
                    EventDescription = ReadString(reader, "EventDescription"),
                    EventType = ReadInt32(reader, "EventType"),
                    NotificationEnabled = ReadBit(reader, "NotificationEnabled")
                });
            }

            ResponseObject responseObj = new ResponseObject();
            responseObj.Data = result;
            return new OkObjectResult(responseObj);
        }
        catch (Exception ex)
        {
            return new BadRequestObjectResult(new ResponseObject
            {
                Status = (int)CommonEnum.ResponseStatus.Failed,
                Message = ex.Message
            });
        }
    }

    [Function("UpdateUserEventSettings")]
    public async Task<IActionResult> UpdateUserEventSettings(
        [HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "users/{id:int}/eventsettings")] HttpRequest req,
        int id)
    {
        try
        {
            var bodyText = await new StreamReader(req.Body).ReadToEndAsync();

            using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
            await conn.OpenAsync();

            var cmd = new SqlCommand(@"
                DELETE FROM dbo.UserEventSettings WHERE UserID = @UserID;

                INSERT INTO dbo.UserEventSettings (UserID, EventCode, NotificationEnabled)
                SELECT @UserID, value, 0
                FROM OPENJSON(@Payload, '$.disabledCodes');", conn);

            cmd.Parameters.AddWithValue("@UserID", id);
            cmd.Parameters.Add("@Payload", SqlDbType.NVarChar, -1).Value = bodyText;

            await cmd.ExecuteNonQueryAsync();

            ResponseObject responseObj = new ResponseObject();
            responseObj.Data = "OK";
            return new OkObjectResult(responseObj);
        }
        catch (Exception ex)
        {
            return new BadRequestObjectResult(new ResponseObject
            {
                Status = (int)CommonEnum.ResponseStatus.Failed,
                Message = ex.Message
            });
        }
    }

}