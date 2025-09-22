using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Data.SqlClient;
using SecurityBoxFunctions.Model.Entities;
using SecurityBoxFunctions.Library;

namespace Winter.SecurityBox;

public class TransactionFunctions
{
    private readonly ILogger<TransactionFunctions> _logger;
    private readonly IConfiguration _configuration;

    public TransactionFunctions(ILogger<TransactionFunctions> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    [Function("GetTransactions")]
    public async Task<IActionResult> Run(
    [HttpTrigger(AuthorizationLevel.Function, "get")] HttpRequest req)
    {
        string msg = "GetTransactions";
        try
        {
            // Parse pagination parameters from query string
            string pageStr = req.Query["page"].FirstOrDefault() ?? "0";
            string pageSizeStr = req.Query["pageSize"].FirstOrDefault() ?? "25";
            string sortField = req.Query["sortField"].FirstOrDefault() ?? "Id";
            string sortDirection = req.Query["sortDirection"].FirstOrDefault() ?? "desc";
            string userId = req.Query["userId"].FirstOrDefault() ?? "";

            if (!int.TryParse(pageStr, out int page) || page < 0)
            {
                page = 0;
            }

            if (!int.TryParse(pageSizeStr, out int pageSize) || pageSize <= 0 || pageSize > 1000)
            {
                pageSize = 25; // Default page size, max 1000 for security
            }

            // Validate sort field to prevent SQL injection
            var allowedSortFields = new[] { "Id", "TimeStamp", "BoxID", "EventCode", "DoorState" };
            if (!allowedSortFields.Contains(sortField))
            {
                sortField = "Id";
            }

            // Validate sort direction
            if (sortDirection.ToLower() != "asc" && sortDirection.ToLower() != "desc")
            {
                sortDirection = "desc";
            }

            var transactions = new List<SecurityBoxHistoryData>();
            int totalCount = 0;

            _logger.LogInformation($"Fetching transactions - Page: {page}, PageSize: {pageSize}, Sort: {sortField} {sortDirection}");

            string connectionString = _configuration["SqlConnectionString"];

            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                await conn.OpenAsync();

                // First, get the total count
                var countQuery = "SELECT COUNT(1) FROM SecurityBoxData";
                using (SqlCommand countCmd = new SqlCommand(countQuery, conn))
                {
                    totalCount = (int)await countCmd.ExecuteScalarAsync();
                }

                // Then get the paginated data
                var query = $@"
                SELECT 
                    s.Id, s.TIMESTAMP, s.BoxID, s.EventCode, s.DoorState, s.FingerprintNum, s.TotalWeight, 
                    s.BoxPosition, ISNULL(e.EventDescription, 'UNKNOWN') AS EventDescription, e.EventType, e.IsC2D
                FROM SecurityBoxData AS s
                LEFT JOIN dbo.EventCodes as e ON e.EventCode = s.EventCode 
                ORDER BY {sortField} {sortDirection.ToUpper()}
                OFFSET @Offset ROWS 
                FETCH NEXT @PageSize ROWS ONLY";

                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@Offset", page * pageSize);
                    cmd.Parameters.AddWithValue("@PageSize", pageSize);

                    using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
                    {
                        while (await reader.ReadAsync())
                        {
                            transactions.Add(new SecurityBoxHistoryData
                            {
                                Id = ConvertDBValue.ReadInt32(reader, "Id"),
                                TimeStamp = ConvertDBValue.ReadDateTime(reader, "TimeStamp") ?? new DateTime(),
                                BoxID = ConvertDBValue.ReadInt64(reader, "BoxID"),
                                EventCode = ConvertDBValue.ReadString(reader, "EventCode"),
                                DoorState = ConvertDBValue.ReadInt64(reader, "DoorState"),
                                FingerprintNum = ConvertDBValue.ReadInt64(reader, "FingerprintNum"),
                                TotalWeight = ConvertDBValue.ReadInt64(reader, "TotalWeight"),
                                BoxPosition = ConvertDBValue.ReadInt64(reader, "BoxPosition"),
                                EventDescription = ConvertDBValue.ReadString(reader, "EventDescription"),
                                EventType = ConvertDBValue.ReadInt32(reader, "EventType"),
                                IsC2D = ConvertDBValue.ReadInt32(reader, "IsC2D")
                            });
                        }
                    }
                }
            }

            // Calculate pagination metadata
            int totalPages = (int)Math.Ceiling((double)totalCount / pageSize);

            // Create paginated response
            var paginatedResponse = new
            {
                transactions = transactions,
                totalCount = totalCount,
                page = page,
                pageSize = pageSize,
                totalPages = totalPages,
                hasNextPage = page < totalPages - 1,
                hasPreviousPage = page > 0
            };

            ResponseObject responseObj = new ResponseObject();
            responseObj.Data = paginatedResponse;

            _logger.LogInformation($"Returned {transactions.Count} transactions out of {totalCount} total");

            return new OkObjectResult(responseObj);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching transactions");
            return new BadRequestObjectResult($"{msg} - Error: {ex.Message}");
        }
    }
}