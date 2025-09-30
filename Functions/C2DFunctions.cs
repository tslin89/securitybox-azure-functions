// SendFingerprintCommand.cs (isolated worker)
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Azure.Devices; // Service SDK
using Azure.Identity;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Data.SqlClient;
using SecurityBoxFunctions.Model.Entities;
using WebPush;
using Microsoft.Azure.Devices.Common.Exceptions;
using SecurityBoxFunctions.Library;

namespace Winter.SecurityBox;

public class A2DFunctions
{
    private readonly ILogger<UserFunctions> _logger;
    private readonly IConfiguration _configuration;
    private readonly ServiceClient _serviceClient;
    private readonly RegistryManager _registry;

    // OPTION 1: Connection string (simpler)
    public A2DFunctions(ILogger<UserFunctions> logger, IConfiguration cfg)
    {
        _logger = logger;
        //var connStr = cfg["IoTHubConnectionString"];
        _configuration = cfg;
        _serviceClient = ServiceClient.CreateFromConnectionString(_configuration["IoTHub2DeviceConnection"]);
        _registry = RegistryManager.CreateFromConnectionString(_configuration["IoTHub2DeviceConnection"]);
    }

    [Function("SendSignalToDevice")]
    public async Task<IActionResult> SendSignalToDevice(
    [HttpTrigger(AuthorizationLevel.Function, "post", Route = "device/sendsignal")] HttpRequestData req)
    {
        var body = await JsonSerializer.DeserializeAsync<StartReq>(req.Body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (body is null || string.IsNullOrWhiteSpace(body.DeviceId))
        {
            return new OkObjectResult(new ResponseObject
            {
                Status = (int)CommonEnum.ResponseStatus.Failed,
                Message = $"Device ID required."
            });
        }

        // Prepare C2D message
        // var message = new Message(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        // {
        //     eventCode = body.eventCode,
        //     fingerprintNum = body.fingerprintNum,
        //     userId = body.UserId,

        //     // temporary added until device changes ready
        //     action = "setup-fingerprint"
        // })))
        // {
        //     MessageId = Guid.NewGuid().ToString(),
        //     ExpiryTimeUtc = DateTime.UtcNow.AddHours(24)
        // };

        var message = new Message(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new C2DObject
        {
            EventCode = body.EventCode,
            UserID = body.UserID,
            BoxID = body.BoxID,
            FingerprintNum = body.FingerprintNum
        })))
        {
            MessageId = Guid.NewGuid().ToString(),
            ExpiryTimeUtc = DateTime.UtcNow.AddHours(24)
        };

        try
        {
            // Verify device exists (optional, since C2D queues even for offline devices)
            var device = await _registry.GetDeviceAsync(body.DeviceId);
            if (device == null || device.Status != DeviceStatus.Enabled)
            {
                _logger.LogWarning("Device {DeviceId} not found or disabled", body.DeviceId);

                return new OkObjectResult(new ResponseObject
                {
                    Status = (int)CommonEnum.ResponseStatus.Failed,
                    Message = $"Device not found or disabled."
                });
            }

            await _serviceClient.SendAsync(body.DeviceId, message);
            _logger.LogInformation("C2D message sent to DeviceId: {DeviceId}, MessageId: {MessageId}", body.DeviceId, message.MessageId);

            if (body.EventCode == "D002") // remove fingerprint
            {
                await removeUserFingerprint(ConvertDBValue.ToInt64(body.UserID), body.BoxID);
                        _logger.LogInformation($"Fingerprint removal completed at IoT device. User: {body.UserID}, BoxID: {body.FingerprintNum} removed from Database.");
            }

            return new OkObjectResult(new ResponseObject
                {
                    Status = (int)CommonEnum.ResponseStatus.Success,
                    Message = $"Message successfully sent to device."
                });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send C2D message to DeviceId: {DeviceId}, Error: {Message}", body.DeviceId, ex.Message);

            return new BadRequestObjectResult(new ResponseObject
            {
                Status = (int)CommonEnum.ResponseStatus.Failed,
                Message = $"Failed to send C2D message to DeviceId: {body.DeviceId}, Error: {ex.Message}"
            });
        }
    }

        private async Task removeUserFingerprint(long userID, long boxID)
    {
        try
        {
            using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
            await conn.OpenAsync();

            var sql = $@"
            UPDATE dbo.UserBoxes 
            SET FingerprintNum = NULL
            WHERE UserID = @UserID AND BoxID = @BoxID";

            var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@UserID", userID);
            cmd.Parameters.AddWithValue("@BoxID", boxID);

            var rowsAffected = await cmd.ExecuteNonQueryAsync();
        }
        catch (Exception ex)
        {
            throw ex;
        }
    }

    private record StartReq(
        string DeviceId,
        int UserID,
        long BoxID,
        long? FingerprintNum,
        string EventCode
    );

    private class C2DObject
    {
        public string EventCode { get; set; }
        public int UserID { get; set; }
        public long BoxID { get; set; }
        public long? FingerprintNum { get; set; }
    }
}
