using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Data.SqlClient;
using azure_functions.Model.Entities;

namespace Winter.SecurityBox;

public class GetTransactions
{
    private readonly ILogger<GetTransactions> _logger;
    private readonly IConfiguration _configuration;

    public GetTransactions(ILogger<GetTransactions> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    [Function("GetTransactions")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "get", "post")] HttpRequest req)
    {
        string msg = "GetTransactions";
        try
        {
            var transactions = new List<IoTDeviceData>();
            _logger.LogInformation("Fetching transactions from Azure SQL Database...");

            string connectionString = _configuration["SqlConnectionString"];

            var query = "SELECT * FROM IoTDeviceData";

            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                await conn.OpenAsync();
                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
                    {
                        while (await reader.ReadAsync())
                        {
                            transactions.Add(new IoTDeviceData
                            {
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

            return new OkObjectResult(transactions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching transactions");
            return new BadRequestObjectResult($"{msg} - Error: {ex.Message}");
            //return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }

    }
}