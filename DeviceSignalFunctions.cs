using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Data.SqlClient;
using SecurityBoxFunctions.Model.Entities;

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

        foreach (EventData eventData in events)
        {
            string msg = Encoding.UTF8.GetString(eventData.EventBody.ToArray());
            _logger.LogInformation($"IoT message received: {msg}");

            signalRMessages.Add(new SignalRMessageAction("newAlert", new object[] { msg }));
        }

        return signalRMessages.ToArray();
    }
}