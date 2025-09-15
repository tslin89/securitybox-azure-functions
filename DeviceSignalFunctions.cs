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

using Azure.Messaging.EventHubs;
using Microsoft.Azure.Functions.Worker;
using System.Text.Json;

namespace Winter.SecurityBox;

public class TestSignals
{

    private readonly ILogger<UserFunctions> _logger;
    private readonly IConfiguration _configuration;

    public TestSignals(ILogger<UserFunctions> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    [Function("TriggerSignalR")]
    [SignalROutput(HubName = "alerts", ConnectionStringSetting = "AzureSignalRConnectionString")]
    public async Task<SignalRMessageAction[]> SendTestSignalRData(
    [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequestData req)
    {
        _logger.LogInformation("TestSignalRAlert function triggered");

        var body = await new StreamReader(req.Body).ReadToEndAsync();

        var signalRMessages = new List<SignalRMessageAction>();

        signalRMessages.Add(new SignalRMessageAction("newAlert", new[] { body }));

        // var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        // await response.WriteStringAsync("SignalR test messages sent!");

        return signalRMessages.ToArray();
    }

    [Function("ProcessSecurityBoxIoTMessage")]
    [SignalROutput(HubName = "alerts")]
    public async Task<SignalRMessageAction[]> ProcessIoTSignal(
            [EventHubTrigger("iothub-ehub-security-b-56317008-6d74c3130",
            Connection = "IoTHubConnectionString",
            ConsumerGroup = "func-consumer")] EventData[] events)
    {
        var signalRMessages = new List<SignalRMessageAction>();
        var pushTasks = new List<Task>();

        foreach (EventData eventData in events)
        {
            string msg = Encoding.UTF8.GetString(eventData.EventBody.ToArray());
            _logger.LogInformation($"IoT message received: {msg}");

            signalRMessages.Add(new SignalRMessageAction("newAlert", new object[] { msg }));

            // 2) Also send Web Push (your helper that loads subs & sends)
            pushTasks.Add(SendWebPushAsyncForMessageAsync(msg));
        }

        // ✅ wait for all pushes before finishing the function
        await Task.WhenAll(pushTasks);

        return signalRMessages.ToArray();
    }

    private async Task<List<StoredPushSubscription>> GetAllSubscriptionsAsync()
    {
        var list = new List<StoredPushSubscription>();
        using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
        await conn.OpenAsync();
        using var cmd = new SqlCommand("SELECT Endpoint, P256dh, Auth FROM dbo.PushSubscriptions", conn);
        using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
            list.Add(new StoredPushSubscription
            {
                Endpoint = r.GetString(0),
                P256dh = r.GetString(1),
                Auth = r.GetString(2)
            });
        return list;
    }

    private async Task SendWebPushAsyncForMessageAsync(string rawJson)
    {
        // Optional: only push for certain events (keeps SignalR realtime for everything)
        // try
        // {
        //     using var doc = JsonDocument.Parse(rawJson);
        //     if (doc.RootElement.TryGetProperty("EventCode", out var ec) &&
        //         !string.Equals(ec.GetString(), "C999", StringComparison.OrdinalIgnoreCase))
        //     {
        //         // Not an alert → skip push
        //         return;
        //     }
        // }
        // catch
        // {
        //     // Not valid JSON – push anyway or skip; up to you
        // }

        // temporarily send code only
        using var doc = JsonDocument.Parse(rawJson);
        doc.RootElement.TryGetProperty("EventCode", out var eventCode);
        doc.RootElement.TryGetProperty("BoxID", out var boxID);

        var title = "SecurityBox Alert";
        var body = $"Box: {boxID.GetString()} - Event Code: {eventCode.GetString()}"; //rawJson           // keep as-is to avoid DateTime format issues
        var url = "/dashboard";      // where you want taps to land in your PWA

        var subs = await GetAllSubscriptionsAsync(); // implement as shown earlier
        if (subs.Count == 0) return;

        await SendWebPushAsync(subs, title, body, url);
    }

    public sealed class PushSubscriptionDtoTest
    {
        public string endpoint { get; set; } = "";
        public long? expirationTime { get; set; }
        public Keys keys { get; set; } = default!;
        public sealed class Keys { public string p256dh { get; set; } = ""; public string auth { get; set; } = ""; }
    }

    // [Function("PushTest")]
    // public async Task<HttpResponseData> PushTest(
    // [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "push/test")] HttpRequestData req)
    // {
    //     var body = await new StreamReader(req.Body).ReadToEndAsync();
    //     var dto = JsonSerializer.Deserialize<PushSubscriptionDtoTest>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

    //     var vapid = new VapidDetails(
    //         _configuration["Vapid:Subject"],
    //         _configuration["Vapid:PublicKey"],
    //         _configuration["Vapid:PrivateKey"]);

    //     var payload = JsonSerializer.Serialize(new { title = "Test Push", body = "Hello from server", url = "/dashboard" });

    //     try
    //     {
    //         var sub = new PushSubscription(dto!.endpoint, dto.keys.p256dh, dto.keys.auth);
    //         await _push.SendNotificationAsync(sub, payload, vapid);
    //         var ok = req.CreateResponse(System.Net.HttpStatusCode.OK);
    //         await ok.WriteStringAsync("sent");
    //         return ok;
    //     }
    //     catch (Exception ex)
    //     {
    //         var bad = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
    //         await bad.WriteStringAsync(ex.ToString());
    //         return bad;
    //     }
    // }

    #region Browser Push-Notifications
    private readonly WebPushClient _push = new();
    private async Task SendWebPushAsync(IEnumerable<StoredPushSubscription> subs, string title, string body, string url)
    {
        var vapid = new VapidDetails(
            _configuration["Vapid:Subject"],
            _configuration["Vapid:PublicKey"],
            _configuration["Vapid:PrivateKey"]);

        var payload = JsonSerializer.Serialize(new { title, body, url });

        foreach (var s in subs)
        {
            try
            {
                var sub = new PushSubscription(s.Endpoint, s.P256dh, s.Auth);
                await _push.SendNotificationAsync(sub, payload, vapid);
                //await _push.SendNotificationAsync(sub, "hello-azure-function", vapid);
                //await _push.SendNotificationAsync(sub, null, vapid);
                _logger.LogInformation("[WebPush-OK] sent to {Endpoint} | {p256} | {auth} | {pbkey}", s.Endpoint, s.P256dh, s.Auth, vapid.PublicKey);
            }
            catch (WebPushException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Gone ||
                                              ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                _logger.LogWarning("[WebPush-ERR] Stale subscription {Endpoint} — deleting. Status {Status}", s.Endpoint, ex.StatusCode);
                await DeleteSubscriptionByEndpointAsync(s.Endpoint);
            }
            catch (WebPushException ex)
            {
                _logger.LogError(ex, "[WebPush-ERR] failed for {Endpoint}. Status {Status}. Body: {Body}",
                    s.Endpoint, ex.StatusCode, ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[WebPush-ERR] Unexpected error sending WebPush to {Endpoint}", s.Endpoint);
            }
        }
    }
    private async Task<List<StoredPushSubscription>> GetSubscriptionsForUserAsync(int userId)
    {
        using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
        await conn.OpenAsync();
        var cmd = new SqlCommand(@"SELECT UserId, Endpoint, P256dh, Auth, CreatedAt, ExpirationTime
                               FROM dbo.PushSubscriptions WHERE UserId=@UserId", conn);
        cmd.Parameters.AddWithValue("@UserId", userId);

        var list = new List<StoredPushSubscription>();
        using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            list.Add(new StoredPushSubscription
            {
                UserId = r.GetInt32(0),
                Endpoint = r.GetString(1),
                P256dh = r.GetString(2),
                Auth = r.GetString(3),
                CreatedAt = r.GetDateTime(4),
                ExpirationTime = r.IsDBNull(5) ? (DateTimeOffset?)null : r.GetDateTime(5)
            });
        }
        return list;
    }

    public sealed class PushSubscriptionDto
    {
        public string UserId { get; set; } = "";
        public JsonElement Subscription { get; set; } // store raw JSON
    }

    [Function("PushSubscribe")]
    public async Task<IActionResult> PushSubscribe(
    [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "push/subscribe")] HttpRequest req)
    {
        var body = await new StreamReader(req.Body).ReadToEndAsync();
        var dto = JsonSerializer.Deserialize<PushSubscribeDto>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (dto is null || dto.Subscription is null) return new BadRequestObjectResult("invalid payload");

        using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
        await conn.OpenAsync();

        // upsert by Endpoint
        var cmd = new SqlCommand(@"
            MERGE dbo.PushSubscriptions AS tgt
            USING (SELECT @Endpoint AS Endpoint) AS src
            ON tgt.Endpoint = src.Endpoint
            WHEN MATCHED THEN UPDATE SET UserId=@UserId, P256dh=@P256dh, Auth=@Auth, ExpirationTime=@Exp
            WHEN NOT MATCHED THEN INSERT (UserId, Endpoint, P256dh, Auth, ExpirationTime)
            VALUES (@UserId, @Endpoint, @P256dh, @Auth, @Exp);", conn);

        cmd.Parameters.AddWithValue("@UserId", dto.UserId);
        cmd.Parameters.AddWithValue("@Endpoint", dto.Subscription.endpoint);
        cmd.Parameters.AddWithValue("@P256dh", dto.Subscription.keys.p256dh);
        cmd.Parameters.AddWithValue("@Auth", dto.Subscription.keys.auth);
        cmd.Parameters.AddWithValue("@Exp", (object?)(dto.Subscription.expirationTime is long ticks
                                      ? DateTimeOffset.FromUnixTimeMilliseconds(ticks) : null) ?? DBNull.Value);

        await cmd.ExecuteNonQueryAsync();
        return new OkResult();
    }

    public sealed class PushUnsubscribeDto { public string endpoint { get; set; } = ""; }

    [Function("PushUnsubscribe")]
    public async Task<IActionResult> PushUnsubscribe(
      [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "push/unsubscribe")] HttpRequest req,
      IConfiguration cfg)
    {
        var body = await new StreamReader(req.Body).ReadToEndAsync();
        var dto = JsonSerializer.Deserialize<PushUnsubscribeDto>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (dto is null || string.IsNullOrWhiteSpace(dto.endpoint)) return new BadRequestObjectResult("invalid");

        using var conn = new SqlConnection(cfg["SqlConnectionString"]);
        await conn.OpenAsync();
        var cmd = new SqlCommand("DELETE FROM dbo.PushSubscriptions WHERE Endpoint=@Endpoint", conn);
        cmd.Parameters.AddWithValue("@Endpoint", dto.endpoint);
        await cmd.ExecuteNonQueryAsync();
        return new OkResult();
    }

    private async Task<int> DeleteSubscriptionByEndpointAsync(string endpoint)
    {
        using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
        await conn.OpenAsync();

        using var cmd = new SqlCommand(
            "DELETE FROM dbo.PushSubscriptions WHERE Endpoint = @Endpoint", conn);
        cmd.Parameters.AddWithValue("@Endpoint", endpoint);

        return await cmd.ExecuteNonQueryAsync(); // rows deleted
    }
    #endregion
}