using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Data.SqlClient;
using SecurityBoxFunctions.Model.Entities;
using System.Text.Json;
using WebPush;

namespace Winter.SecurityBox;

public class DashboardFunctions
{
    private readonly ILogger<UserFunctions> _logger;
    private readonly IConfiguration _configuration;

    public DashboardFunctions(ILogger<UserFunctions> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    [Function("DashboardOverview")]
    public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = "dashboard/overview")] HttpRequest req)
    {
        // Query params
        int days = int.TryParse(req.Query["days"], out var d) ? d : 14;
        int recent = int.TryParse(req.Query["recent"], out var r) ? r : 25;
        int activeMinutes = int.TryParse(req.Query["activeMinutes"], out var a) ? a : 10;

        // DB
        var connStr = Environment.GetEnvironmentVariable("SqlConnectionString");
        if (string.IsNullOrWhiteSpace(connStr))
            return new BadRequestObjectResult("Missing SqlConnectionString app setting");

        // Multi-select batch: NO hardcoded codes; we group by EventCode and let the client map labels.
        var sql = @"
            -- 1) Total boxes
            SELECT COUNT(*) AS totalBoxes FROM dbo.Boxes WHERE IsEnabled = 1;

            -- 2) Active boxes (seen in last @activeMinutes)
            WITH latest AS (
            SELECT BoxID, MAX([Timestamp]) AS lastSeen
            FROM SecurityBoxData
            GROUP BY BoxID
            )
            SELECT COUNT(*) AS activeBoxes
            FROM latest
            WHERE lastSeen >= DATEADD(minute, -@activeMinutes, SYSUTCDATETIME());

            -- 3) Open doors now (latest state per box)
            WITH lastState AS (
            SELECT BoxID, DoorState,
                    ROW_NUMBER() OVER (PARTITION BY BoxID ORDER BY [Timestamp] DESC) AS rn
            FROM SecurityBoxData
            )
            SELECT COUNT(*) AS openDoorsNow
            FROM lastState
            WHERE rn = 1 AND DoorState = 1;

            -- 4) Per-day counts by EventCode (last @days days)
            SELECT CAST([Timestamp] AS date) AS [Date], EventCode, COUNT(*) AS [Count]
            FROM SecurityBoxData
            WHERE [Timestamp] >= DATEADD(day, -@days, CAST(SYSUTCDATETIME() AS date))
            GROUP BY CAST([Timestamp] AS date), EventCode
            ORDER BY [Date];

            -- 5) Weight trend (avg per day)
            SELECT CAST([Timestamp] AS date) AS [Date], AVG(CAST(TotalWeight AS float)) AS avgWeight
            FROM SecurityBoxData
            WHERE [Timestamp] >= DATEADD(day, -@days, CAST(SYSUTCDATETIME() AS date))
            GROUP BY CAST([Timestamp] AS date)
            ORDER BY [Date];

            -- 6) Recent events
            SELECT TOP (@recent)
            Id, [Timestamp], BoxID, EventCode, DoorState, FingerprintNum, TotalWeight, BoxPosition
            FROM SecurityBoxData
            ORDER BY [Timestamp] DESC;

            -- 7) Totals since start (by EventCode)
            SELECT EventCode, COUNT(*) AS total
            FROM SecurityBoxData
            WHERE [Timestamp] >= DATEADD(day, -@days, CAST(SYSUTCDATETIME() AS date))
            GROUP BY EventCode
            ORDER BY EventCode;

            -- 8) Top boxes by incidents (by EventCode; client can decide which are 'incidents')
            SELECT BoxID, EventCode, COUNT(*) AS total
            FROM SecurityBoxData
            WHERE [Timestamp] >= DATEADD(day, -@days, CAST(SYSUTCDATETIME() AS date))
            GROUP BY BoxID, EventCode
            ORDER BY total DESC;";

        var response = new DashboardOverviewDto
        {
            Summary = new SummaryDto(),
            PerDayCounts = new List<PerDayCountDto>(),
            WeightSeries = new List<WeightPointDto>(),
            RecentEvents = new List<RecentEventDto>(),
            CountsSinceStart = new List<CodeTotalDto>(),
            TopBoxesIncidents = new List<TopBoxIncidentDto>(),
        };

        using var conn = new SqlConnection(connStr);
        await conn.OpenAsync();
        using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@days", days);
        cmd.Parameters.AddWithValue("@recent", recent);
        cmd.Parameters.AddWithValue("@activeMinutes", activeMinutes);

        using var reader = await cmd.ExecuteReaderAsync();

        // 1) totalBoxes
        if (await reader.ReadAsync())
            response.Summary.TotalBoxes = reader.GetInt32(0);

        // 2) activeBoxes
        await reader.NextResultAsync();
        if (await reader.ReadAsync())
            response.Summary.ActiveBoxes = reader.GetInt32(0);

        // 3) openDoorsNow
        await reader.NextResultAsync();
        if (await reader.ReadAsync())
            response.Summary.OpenDoorsNow = reader.GetInt32(0);

        // 4) perDayCounts
        await reader.NextResultAsync();
        while (await reader.ReadAsync())
        {
            response.PerDayCounts.Add(new PerDayCountDto
            {
                Date = reader.GetDateTime(0).ToString("yyyy-MM-dd"),
                EventCode = reader.GetString(1),
                Count = reader.GetInt32(2),
            });
        }

        // 5) weightSeries
        await reader.NextResultAsync();
        while (await reader.ReadAsync())
        {
            response.WeightSeries.Add(new WeightPointDto
            {
                Date = reader.GetDateTime(0).ToString("yyyy-MM-dd"),
                AvgWeight = reader.IsDBNull(1) ? 0 : Convert.ToDouble(reader[1]),
            });
        }

        // 6) recentEvents
        await reader.NextResultAsync();
        while (await reader.ReadAsync())
        {
            try
            {
                var Id = reader.GetInt32(0);
                var Timestamp = reader.GetDateTime(1);
                var BoxID = reader.GetInt64(2);
                var EventCode = reader.GetString(3);
                var DoorState = reader.IsDBNull(4) ? (long?)null : reader.GetInt64(4);
                var FingerprintNum = reader.IsDBNull(5) ? (long?)null : reader.GetInt64(5);
                var TotalWeight = reader.IsDBNull(6) ? (double?)null : Convert.ToDouble(reader[6]);
                var BoxPosition = reader.IsDBNull(7) ? (long?)null : reader.GetInt64(7);
            }
            catch (Exception ex)
            {
                string msg = ex.Message;

                string msg2 = msg + 1;
            }
            response.RecentEvents.Add(new RecentEventDto
            {
                Id = reader.GetInt32(0),
                Timestamp = reader.GetDateTime(1),
                BoxID = reader.GetInt64(2),
                EventCode = reader.GetString(3),
                DoorState = reader.IsDBNull(4) ? (long?)null : reader.GetInt64(4),
                FingerprintNum = reader.IsDBNull(5) ? (long?)null : reader.GetInt64(5),
                TotalWeight = reader.IsDBNull(6) ? (double?)null : Convert.ToDouble(reader[6]),
                BoxPosition = reader.IsDBNull(7) ? (int?)null : reader.GetInt64(7),
            });
        }

        // 7) countsSinceStart
        await reader.NextResultAsync();
        while (await reader.ReadAsync())
        {
            response.CountsSinceStart.Add(new CodeTotalDto
            {
                EventCode = reader.GetString(0),
                Total = reader.GetInt32(1),
            });
        }

        // 8) topBoxesIncidents
        await reader.NextResultAsync();
        while (await reader.ReadAsync())
        {
            response.TopBoxesIncidents.Add(new TopBoxIncidentDto
            {
                BoxID = reader.GetInt64(0),
                EventCode = reader.GetString(1),
                Total = reader.GetInt32(2),
            });
        }

        return new OkObjectResult(response);
    }

    // DTOs
    public class DashboardOverviewDto
    {
        public SummaryDto Summary { get; set; } = default!;
        public List<PerDayCountDto> PerDayCounts { get; set; } = default!;
        public List<WeightPointDto> WeightSeries { get; set; } = default!;
        public List<RecentEventDto> RecentEvents { get; set; } = default!;
        public List<CodeTotalDto> CountsSinceStart { get; set; } = default!;
        public List<TopBoxIncidentDto> TopBoxesIncidents { get; set; } = default!;
    }
    public class SummaryDto
    {
        public int TotalBoxes { get; set; }
        public int ActiveBoxes { get; set; }
        public int OpenDoorsNow { get; set; }
    }
    public class PerDayCountDto
    {
        public string Date { get; set; } = default!;
        public string EventCode { get; set; } = default!;
        public int Count { get; set; }
    }
    public class WeightPointDto
    {
        public string Date { get; set; } = default!;
        public double AvgWeight { get; set; }
    }
    public class RecentEventDto
    {
        public int Id { get; set; }
        public DateTime Timestamp { get; set; }
        public long BoxID { get; set; }
        public string EventCode { get; set; } = default!;
        public long? DoorState { get; set; }
        public long? FingerprintNum { get; set; }
        public double? TotalWeight { get; set; }
        public long? BoxPosition { get; set; }
    }
    public class CodeTotalDto
    {
        public string EventCode { get; set; } = default!;
        public int Total { get; set; }
    }
    public class TopBoxIncidentDto
    {
        public long BoxID { get; set; }
        public string EventCode { get; set; } = default!;
        public int Total { get; set; }
    }
}