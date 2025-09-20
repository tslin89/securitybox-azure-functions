using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Data.SqlClient;
using SecurityBoxFunctions.Model.Entities;

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

            var transactions = new List<SecurityBoxData>();
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
                SELECT * FROM SecurityBoxData 
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
                            transactions.Add(new SecurityBoxData
                            {
                                Id = reader.GetInt32(reader.GetOrdinal("Id")),
                                TimeStamp = reader.GetDateTime(reader.GetOrdinal("TimeStamp")),
                                BoxID = reader.GetInt64(reader.GetOrdinal("BoxID")),
                                EventCode = reader.GetString(reader.GetOrdinal("EventCode")),
                                DoorState = reader.IsDBNull(reader.GetOrdinal("DoorState")) ? null : Convert.ToInt64(reader.GetValue(reader.GetOrdinal("DoorState"))),
                                FingerprintNum = reader.IsDBNull(reader.GetOrdinal("FingerprintNum")) ? null : Convert.ToInt64(reader.GetValue(reader.GetOrdinal("FingerprintNum"))),
                                TotalWeight = reader.IsDBNull(reader.GetOrdinal("TotalWeight")) ? null : Convert.ToSingle(reader.GetValue(reader.GetOrdinal("TotalWeight"))),
                                BoxPosition = reader.IsDBNull(reader.GetOrdinal("BoxPosition")) ? null : Convert.ToInt64(reader.GetValue(reader.GetOrdinal("BoxPosition")))
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

    // [Function("GetLastEventData")]
    // public async Task<IActionResult> GetLastEventData(
    // [HttpTrigger(AuthorizationLevel.Function, "get", Route = "transactions/lastevent")] HttpRequest req)
    // {
    //     try
    //     {
    //         // Parse pagination parameters from query string
    //         string boxId = req.Query["boxID"].FirstOrDefault() ?? "0";
    //         string userId = req.Query["userID"].FirstOrDefault() ?? ""; // use later if necessary


    //         List<BoxEventDataDto> result = new List<BoxEventDataDto>();
    //         using (SqlConnection conn = new SqlConnection(_configuration["SqlConnectionString"]))
    //         {
    //             await conn.OpenAsync();

    //             // Then get the paginated data
    //             var query = $@"
    //             SELECT
    //                 b.BoxID,
    //                 b.DeviceID,
    //                 b.Description,
    //                 s.TimeStamp,
    //                 s.EventCode,
    //                 s.DoorState,
    //                 s.FingerprintNum,
    //                 s.TotalWeight,
    //                 s.BoxPosition,
    //                 s.ReceivedTime
    //                 FROM dbo.Boxes AS b
    //                 OUTER APPLY (
    //                     SELECT TOP 1 s.*
    //                     FROM dbo.SecurityBoxData AS s
    //                     WHERE s.BoxID = b.BoxID
    //                     ORDER BY s.ReceivedTime DESC, s.Id DESC
    //                     ) AS s
    //             WHERE (@BoxID IS NULL OR b.BoxID = @BoxID)
    //             AND b.IsEnabled = 1
    //             ORDER BY b.BoxID;";

    //             using (SqlCommand cmd = new SqlCommand(query, conn))
    //             {
    //                 cmd.Parameters.AddWithValue("@BoxID", boxId == "0" ? DBNull.Value : boxId);

    //                 using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
    //                 {
    //                     while (await reader.ReadAsync())
    //                     {
    //                         result.Add(new BoxEventDataDto
    //                         {
    //                             TimeStamp = reader.IsDBNull(reader.GetOrdinal("TimeStamp")) ? null : reader.GetDateTime(reader.GetOrdinal("TimeStamp")),
    //                             BoxID = reader.GetInt64(reader.GetOrdinal("BoxID")),
    //                             EventCode = reader.IsDBNull(reader.GetOrdinal("EventCode")) ? null : reader.GetString(reader.GetOrdinal("EventCode")),
    //                             DoorState = reader.IsDBNull(reader.GetOrdinal("DoorState")) ? null : Convert.ToInt64(reader.GetValue(reader.GetOrdinal("DoorState"))),
    //                             FingerprintNum = reader.IsDBNull(reader.GetOrdinal("FingerprintNum")) ? null : Convert.ToInt64(reader.GetValue(reader.GetOrdinal("FingerprintNum"))),
    //                             TotalWeight = reader.IsDBNull(reader.GetOrdinal("TotalWeight")) ? null : Convert.ToSingle(reader.GetValue(reader.GetOrdinal("TotalWeight"))),
    //                             BoxPosition = reader.IsDBNull(reader.GetOrdinal("BoxPosition")) ? null : Convert.ToInt64(reader.GetValue(reader.GetOrdinal("BoxPosition"))),
    //                             ReceivedTime = reader.IsDBNull(reader.GetOrdinal("ReceivedTime")) ? null : reader.GetDateTime(reader.GetOrdinal("ReceivedTime")),
    //                             DeviceID = reader.GetString(reader.GetOrdinal("DeviceID")),
    //                             Description = reader.GetString(reader.GetOrdinal("Description")),
    //                         });
    //                     }
    //                 }
    //             }
    //         }

    //         ResponseObject responseObj = new ResponseObject();
    //         responseObj.Data = result;

    //         return new OkObjectResult(responseObj);
    //     }
    //     catch (Exception ex)
    //     {
    //         _logger.LogError(ex, "Error fetching transactions");
    //         return new BadRequestObjectResult($"Error: {ex.Message}");
    //     }
    // }
    
    
}