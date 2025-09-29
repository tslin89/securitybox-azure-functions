using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Data.SqlClient;
using SecurityBoxFunctions.Model.Entities;
using WebPush;
using Azure.Messaging.EventHubs;
using System.Text.Json;
using System.Data;
using System.Net;
using SecurityBoxFunctions.Library;

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

    [Function("ProcessSecurityBoxIoTMessage")]
    [SignalROutput(HubName = "alerts")]
    public async Task<SignalRMessageAction[]> ProcessIoTSignal(
        [EventHubTrigger("iothub-ehub-security-b-56317008-6d74c3130",
        Connection = "IoTHubConnectionString",
        ConsumerGroup = "func-consumer")] EventData[] events)
    {
        var signalRMessages = new List<SignalRMessageAction>();
        var pushTasks = new List<Task>();

        using var conn = new SqlConnection(_configuration["SqlConnectionString"]);
        await conn.OpenAsync();
        foreach (EventData eventData in events)
        {
            string msg = Encoding.UTF8.GetString(eventData.EventBody.ToArray());
            _logger.LogInformation($"IoT message received: {msg}");

            // save to database
            var sensorBoxData = JsonSerializer.Deserialize<SecurityBoxData>(msg);

            bool inserted = await SaveToDatabase(conn, sensorBoxData);

            if (inserted)
            {
                if (ConvertDBValue.ToInt64(sensorBoxData.FingerprintNum) != 0 &&
                    ConvertDBValue.ToInt64(sensorBoxData.UserID) != 0 &&
                    ConvertDBValue.ToInt64(sensorBoxData.BoxID) != 0)
                {
                    if (sensorBoxData.EventCode == "C201") // fingerprint added
                    {
                        await UpdateFingerprintNum(conn, sensorBoxData);
                        _logger.LogInformation($"Fingerprint setup completed at IoT device. User: {sensorBoxData.UserID}, FingerprintNum: {sensorBoxData.FingerprintNum}.");
                    }
                    else if (sensorBoxData.EventCode == "C202") // fingerprint removed
                    {
                        // currently being removed from database after successful signal sent to device
                        // await removeUserFingerprint(ConvertDBValue.ToInt64(sensorBoxData.UserID), sensorBoxData.BoxID);
                        // _logger.LogInformation($"Fingerprint removal completed at IoT device. User: {sensorBoxData.UserID}, BoxID: {sensorBoxData.FingerprintNum} removed from Database.");
                    }
                }

                var (signalRUserIDs, subs, msgMeta) = await GetNotificationRecipientsAsync(conn, sensorBoxData.BoxID, sensorBoxData.EventCode);

                // 1) Trigger SignalR
                foreach (var uid in signalRUserIDs)
                {
                    signalRMessages.Add(new SignalRMessageAction("newAlert")  // <-- target here
                    {
                        UserId = uid.ToString(),
                        Arguments = new object[] { msg }
                    });
                }

                // Web Push — build payload once, send to exact subs
                string boxDesc = msgMeta.BoxDescription ?? $"Box {sensorBoxData.BoxID}";
                boxDesc = boxDesc.TrimEnd();
                string boxShort = boxDesc.Length > 20 ? boxDesc[..20] + "..." : boxDesc;

                string body = $"{msgMeta.EventDescription ?? "Unknown Event"} \n<{boxShort}>";
                string title = $"SecurityBox Alert";
                string url = "/dashboard";

                pushTasks.Add(SendWebPushBatchAsync(subs, title, body, url));
            }
        }
        await Task.WhenAll(pushTasks);

        return signalRMessages.ToArray();
    }

    private async Task SendWebPushBatchAsync(IEnumerable<PushSub> subs, string title, string body, string url)
    {
        if (subs is null) return;

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
                _logger.LogInformation("[WebPush-OK] {Endpoint}", s.Endpoint);
            }
            catch (WebPushException ex) when (ex.StatusCode == HttpStatusCode.Gone || ex.StatusCode == HttpStatusCode.NotFound)
            {
                _logger.LogWarning("[WebPush-STALE] {Endpoint} ({Status}) → deleting", s.Endpoint, ex.StatusCode);
                await DeleteSubscriptionByEndpointAsync(s.Endpoint);
            }
            catch (WebPushException ex)
            {
                _logger.LogError(ex, "[WebPush-ERR] {Endpoint} ({Status})", s.Endpoint, ex.StatusCode);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[WebPush-ERR] Unexpected for {Endpoint}", s.Endpoint);
            }
        }
    }

    public sealed class PushSub
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string Endpoint { get; set; } = "";
        public string P256dh { get; set; } = "";
        public string Auth { get; set; } = "";
        public DateTime? ExpirationTime { get; set; }
    }

    public sealed class MsgMeta
    {
        public string EventCode { get; set; } = "";
        public string? EventDescription { get; set; }
        public string? BoxDescription { get; set; }
    }

    private async Task<(List<int> UserIds, List<PushSub> Subs, MsgMeta Meta)> GetNotificationRecipientsAsync(
        SqlConnection conn, long boxId, string eventCode)
    {
        const string sql = @"
                CREATE TABLE #EligibleUsers (UserID int NOT NULL PRIMARY KEY);

                INSERT INTO #EligibleUsers(UserID)
                SELECT u.UserID
                FROM dbo.Users u
                LEFT JOIN dbo.UserEventSettings s
                    ON s.UserID = u.UserID AND s.EventCode = @EventCode
                WHERE 1=1
                AND ISNULL(u.IsEnabled, 1) = 1
                AND COALESCE(s.NotificationEnabled, 1) = 1;  -- default allow

                -- 1) SignalR users
                SELECT eu.UserID
                FROM #EligibleUsers eu;

                -- 2) Push subscriptions for those users
                SELECT ps.Id, ps.UserId, ps.Endpoint, ps.P256dh, ps.Auth, ps.ExpirationTime
                FROM #EligibleUsers eu
                JOIN dbo.PushSubscriptions ps ON ps.UserId = eu.UserID
                WHERE ps.ExpirationTime IS NULL OR ps.ExpirationTime > SYSUTCDATETIME();

                -- 3) Message metadata: Event + Box descriptions
                SELECT
                @EventCode AS EventCode,
                ec.EventDescription,
                b.Description AS BoxDescription
                FROM dbo.EventCodes ec
                LEFT JOIN dbo.Boxes b ON b.BoxID = @BoxID
                WHERE ec.EventCode = @EventCode;
                ";
        using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add("@BoxID", SqlDbType.BigInt).Value = boxId;
        cmd.Parameters.Add("@EventCode", SqlDbType.NVarChar, 10).Value = eventCode;

        var userIds = new List<int>();
        var subs = new List<PushSub>();
        var meta = new MsgMeta { EventCode = eventCode };

        using var rdr = await cmd.ExecuteReaderAsync();

        // Result set 1: user IDs for SignalR
        while (await rdr.ReadAsync())
            userIds.Add(rdr.GetInt32(0));

        // Result set 2: push subscriptions
        if (await rdr.NextResultAsync())
        {
            int oId = rdr.GetOrdinal("Id"),
                oUserId = rdr.GetOrdinal("UserId"),
                oEndpoint = rdr.GetOrdinal("Endpoint"),
                oP256 = rdr.GetOrdinal("P256dh"),
                oAuth = rdr.GetOrdinal("Auth"),
                oExp = rdr.GetOrdinal("ExpirationTime");

            while (await rdr.ReadAsync())
            {
                subs.Add(new PushSub
                {
                    Id = rdr.GetInt32(oId),
                    UserId = rdr.GetInt32(oUserId),
                    Endpoint = rdr.GetString(oEndpoint),
                    P256dh = rdr.GetString(oP256),
                    Auth = rdr.GetString(oAuth),
                    ExpirationTime = rdr.IsDBNull(oExp) ? (DateTime?)null : rdr.GetDateTime(oExp)
                });
            }
        }

        // 3) meta
        if (await rdr.NextResultAsync() && await rdr.ReadAsync())
        {
            meta.EventDescription = rdr.IsDBNull(1) ? null : rdr.GetString(1);
            meta.BoxDescription = rdr.IsDBNull(2) ? null : rdr.GetString(2);
        }

        return (userIds, subs, meta);
    }


    private async Task UpdateFingerprintNum(SqlConnection conn, SecurityBoxData data)
    {
        var cmd = new SqlCommand(
            @"
            IF EXISTS (SELECT 1 FROM UserBoxes WHERE UserID = @UserID AND BoxID = @BoxID)
                UPDATE dbo.UserBoxes SET FingerprintNum = @FingerprintNum WHERE 
                UserID = @UserID AND BoxID = @BoxID;
            ELSE
                INSERT INTO dbo.UserBoxes (UserID, BoxID, FingerprintNum)
                VALUES (@UserID, @BoxID, @FingerprintNum);", conn);

        cmd.Parameters.Add("@UserID", SqlDbType.Int).Value = data.UserID;
        cmd.Parameters.Add("@BoxID", SqlDbType.Int).Value = data.BoxID;
        cmd.Parameters.Add("@fingerprintNum", SqlDbType.BigInt).Value = data.FingerprintNum;

        await cmd.ExecuteNonQueryAsync();
    }

    private async Task<bool> SaveToDatabase(SqlConnection conn, SecurityBoxData data)
    {
        var sql = @"
            SET NOCOUNT ON;
            SET XACT_ABORT ON;
            SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
            BEGIN TRAN;
            IF NOT EXISTS (
                SELECT 1 FROM dbo.SecurityBoxData
                WHERE 
                    1=1
                    AND TimeStamp = @TimeStamp  
                    AND BoxID = @BoxID 
                    AND EventCode = @EventCode  
                    AND ((DoorState = @DoorState) OR (DoorState IS NULL AND @DoorState IS NULL))
                    AND ((FingerprintNum = @FingerprintNum) OR (FingerprintNum IS NULL AND @FingerprintNum IS NULL))
                    AND ((TotalWeight = @TotalWeight) OR (TotalWeight IS NULL AND @TotalWeight IS NULL))
                    AND ((BoxPosition = @BoxPosition) OR (BoxPosition IS NULL AND @BoxPosition IS NULL))
                    AND ((SecurityStatus = @SecurityStatus) OR (SecurityStatus IS NULL AND @SecurityStatus IS NULL))
            )
            BEGIN
                INSERT INTO dbo.SecurityBoxData (
                    TimeStamp, BoxID, EventCode, DoorState, FingerprintNum, TotalWeight, BoxPosition, SecurityStatus, ReceivedTime
                ) VALUES (
                    @TimeStamp, @BoxID, @EventCode, @DoorState, @FingerprintNum, @TotalWeight, @BoxPosition, @SecurityStatus, @ReceivedTime
                );
                SELECT CAST(1 AS bit);
            END
            ELSE
                SELECT CAST(0 AS bit);
            COMMIT;";

        using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add("@TimeStamp", SqlDbType.DateTime).Value = (object)data.TimeStamp;
        cmd.Parameters.Add("@BoxID", SqlDbType.BigInt).Value = data.BoxID;
        cmd.Parameters.Add("@EventCode", SqlDbType.NVarChar).Value = (object?)data.EventCode ?? "UNKNOWN";
        cmd.Parameters.Add("@DoorState", SqlDbType.BigInt).Value = (object?)data.DoorState ?? DBNull.Value;
        cmd.Parameters.Add("@FingerprintNum", SqlDbType.BigInt).Value = (object?)data.FingerprintNum ?? DBNull.Value;
        cmd.Parameters.Add("@TotalWeight", SqlDbType.Float).Value = (object?)data.TotalWeight ?? DBNull.Value;
        cmd.Parameters.Add("@BoxPosition", SqlDbType.BigInt).Value = (object?)data.BoxPosition ?? DBNull.Value;
        cmd.Parameters.Add("@SecurityStatus", SqlDbType.BigInt).Value = (object?)data.SecurityStatus ?? DBNull.Value;
        cmd.Parameters.Add("@ReceivedTime", SqlDbType.DateTime).Value = DateTime.Now;

        var inserted = (bool)await cmd.ExecuteScalarAsync();

        return inserted;
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

    public sealed class PushSubscriptionDtoTest
    {
        public string endpoint { get; set; } = "";
        public long? expirationTime { get; set; }
        public Keys keys { get; set; } = default!;
        public sealed class Keys { public string p256dh { get; set; } = ""; public string auth { get; set; } = ""; }
    }

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
                               FROM dbo.PushSubscriptions WHERE UserId=@UserId;", conn);
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
            "DELETE FROM dbo.PushSubscriptions WHERE Endpoint = @Endpoint;", conn);
        cmd.Parameters.AddWithValue("@Endpoint", endpoint);

        return await cmd.ExecuteNonQueryAsync(); // rows deleted
    }
    #endregion
}