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

public class PushNotificationFunctions
{
    private readonly ILogger<TransactionFunctions> _logger;
    private readonly IConfiguration _configuration;

    public PushNotificationFunctions(ILogger<TransactionFunctions> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    

}