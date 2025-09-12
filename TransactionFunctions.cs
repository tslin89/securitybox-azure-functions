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
            var transactions = new List<SecurityBoxData>();
            _logger.LogInformation("Fetching transactions from Azure SQL Database...");

            string connectionString = _configuration["SqlConnectionString"];

            var query = "SELECT * FROM SecurityBoxData";

            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                await conn.OpenAsync();
                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
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
                                DoorState = reader.IsDBNull(reader.GetOrdinal("DoorState")) ? null : Convert.ToInt32(reader.GetValue(reader.GetOrdinal("DoorState"))),
                                FingerprintNum = reader.IsDBNull(reader.GetOrdinal("FingerprintNum")) ? null : Convert.ToInt32(reader.GetValue(reader.GetOrdinal("FingerprintNum"))),
                                TotalWeight = reader.IsDBNull(reader.GetOrdinal("TotalWeight")) ? null : Convert.ToSingle(reader.GetValue(reader.GetOrdinal("TotalWeight"))),
                                BoxPosition = reader.IsDBNull(reader.GetOrdinal("BoxPosition")) ? null : Convert.ToInt64(reader.GetValue(reader.GetOrdinal("BoxPosition")))
                            });
                        }
                    }
                }
            }

            ResponseObject responseObj = new ResponseObject();
            responseObj.Data = transactions;

            return new OkObjectResult(responseObj);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching transactions");
            return new BadRequestObjectResult($"{msg} - Error: {ex.Message}");
            //return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }

    }
}