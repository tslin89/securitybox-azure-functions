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

    // OPTION 2: AAD (no secrets); uncomment this and remove the ctor above
    // public SendFingerprintCommand(IConfiguration cfg)
    // {
    //     var hostName = cfg["IOTHUB_HOSTNAME"]; // e.g. myhub.azure-devices.net
    //     _serviceClient = ServiceClient.Create(hostName, new DefaultAzureCredential());
    // }

    // [Function("SendFingerprintCommand")]
    // public async Task<HttpResponseData> SendFingerprintSetupCommand(
    //     [HttpTrigger(AuthorizationLevel.Function, "post", Route = "fingerprint/start")] HttpRequestData req)
    // {
    //     var body = await JsonSerializer.DeserializeAsync<StartReq>(req.Body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    //     if (body is null || string.IsNullOrWhiteSpace(body.DeviceId))
    //     {
    //         var bad = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
    //         await bad.WriteStringAsync("deviceId is required");
    //         return bad;
    //     }

    //     // Prepare a direct method call
    //     var method = new CloudToDeviceMethod("startFingerprintEnrollment")
    //     {
    //         ResponseTimeout = TimeSpan.FromSeconds(30),
    //         ConnectionTimeout = TimeSpan.FromSeconds(10)
    //     };
    //     method.SetPayloadJson(JsonSerializer.Serialize(new
    //     {
    //         userId = body.UserId,
    //         action = "start",
    //         timeoutSec = 60,
    //         correlationId = body.CorrelationId ?? Guid.NewGuid().ToString()
    //     }));

    //     try
    //     {
    //         // Check if device is accessible via registry
    //         var device = await _registry.GetDeviceAsync(body.DeviceId);
    //         _logger.LogInformation("Device found and enabled: {DeviceId}, Status: {Status}", device.Id, device.Status);

    //         // Optional: Get twin to check last activity (rough online indicator)
    //         var twin = await _registry.GetTwinAsync(body.DeviceId);
    //         _logger.LogInformation("Device twin last activity: {LastActivity}", twin.LastActivityTime?.ToString() ?? "Unknown");

    //         // Proceed with method invoke...
    //         var result = await _serviceClient.InvokeDeviceMethodAsync(body.DeviceId, method);
    //         var ok = req.CreateResponse(System.Net.HttpStatusCode.OK);
    //         await ok.WriteAsJsonAsync(new
    //         {
    //             status = result.Status,                     // 200, 404 if method not found, 500 if device error, etc.
    //             payload = result.GetPayloadAsJson()
    //         });
    //         return ok;
    //     }
    //     catch (DeviceNotFoundException)
    //     {
    //         var nf = req.CreateResponse(System.Net.HttpStatusCode.NotFound);
    //         await nf.WriteStringAsync("Device not found or offline.");
    //         return nf;
    //     }
    //     catch (Exception ex)
    //     {
    //         var err = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
    //         await err.WriteStringAsync($"Invoke failed: {ex.Message}");
    //         return err;
    //     }
    // }

    [Function("SendFingerprintCommand")]
    public async Task<HttpResponseData> SendFingerprintSetupCommand(
    [HttpTrigger(AuthorizationLevel.Function, "post", Route = "fingerprint/start")] HttpRequestData req)
    {
        var body = await JsonSerializer.DeserializeAsync<StartReq>(req.Body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (body is null || string.IsNullOrWhiteSpace(body.DeviceId))
        {
            var bad = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("deviceId is required");
            return bad;
        }

        // Prepare C2D message
        var message = new Message(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            userId = body.UserId,
            action = "setup-fingerprint",
            transactionID = body.CorrelationId ?? Guid.NewGuid().ToString()
        })))
        {
            MessageId = Guid.NewGuid().ToString(),
            ExpiryTimeUtc = DateTime.UtcNow.AddHours(24) // Optional: Set TTL
        };

        try
        {
            // Verify device exists (optional, since C2D queues even for offline devices)
            var device = await _registry.GetDeviceAsync(body.DeviceId);
            if (device == null || device.Status != DeviceStatus.Enabled)
            {
                _logger.LogWarning("Device {DeviceId} not found or disabled", body.DeviceId);
                var nf = req.CreateResponse(System.Net.HttpStatusCode.NotFound);
                await nf.WriteStringAsync("Device not found or disabled.");
                return nf;
            }

            // Send C2D message
            await _serviceClient.SendAsync(body.DeviceId, message);
            _logger.LogInformation("C2D message sent to DeviceId: {DeviceId}, MessageId: {MessageId}", body.DeviceId, message.MessageId);

            var ok = req.CreateResponse(System.Net.HttpStatusCode.OK);
            await ok.WriteAsJsonAsync(new { status = "sent", messageId = message.MessageId });
            return ok;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send C2D message to DeviceId: {DeviceId}, Error: {Message}", body.DeviceId, ex.Message);
            var err = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
            await err.WriteStringAsync($"Send failed: {ex.Message}");
            return err;
        }
    }

    private record StartReq(string DeviceId, int UserId, string? CorrelationId);

    // [Function("CheckFingerprintStatus")]
    // public async Task<HttpResponseData> Run(
    //     [HttpTrigger(AuthorizationLevel.Function, "get", Route = "fingerprint/status/{deviceId}")] HttpRequestData req,
    //     string deviceId)
    // {
    //     var twin = await _registry.GetTwinAsync(deviceId);

    //     // Expecting this shape from device code above:
    //     // reported.fingerprint.lastEnrollment = { userId, status, num, updatedAt, correlationId }
    //     var reported = twin.Properties.Reported;

    //     var fp = reported["fingerprint"]?["lastEnrollment"];
    //     var status = fp?["status"]?.ToString();
    //     var num = (int?)fp?["num"];

    //     var ok = req.CreateResponse(System.Net.HttpStatusCode.OK);
    //     await ok.WriteAsJsonAsync(new { status = status ?? "waiting", fingerprintNum = num });
    //     return ok;
    // }
}
