# Winter Security Box – Azure Functions Backend

The serverless backend for the Winter Security Box IoT Security Management Platform, developed using C# and Azure Functions.

The backend provides REST APIs, processes IoT device messages, manages security-box operations and delivers real-time notifications to the React web application.

## Overview

Winter Security Box is an IoT-enabled parcel security system designed to provide secure parcel storage, remote monitoring and controlled access through fingerprint authentication.

This repository contains the backend services responsible for communication between the web application, Azure cloud services and IoT security devices.

Built using Azure Functions and the .NET isolated worker model, the backend processes device-to-cloud messages, sends cloud-to-device commands, manages application data and distributes real-time security events.

## Architecture

```text
                   React Web Application
                            |
                  +---------+---------+
                  |                   |
                  v                   v
              REST APIs          SignalR Client
                  |                   ^
                  v                   |
          Azure Functions             |
                  |                   |
       +----------+----------+        |
       |          |          |        |
       v          v          v        |
   Azure SQL   Azure IoT   Azure      |
   Database      Hub      SignalR ----+
                  |
          +-------+-------+
          |               |
          v               v
      IoT Device      Event Hub
                          |
                          v
                   Azure Functions
                          |
                 +--------+--------+
                 |                 |
                 v                 v
             Azure SQL       Push Notifications
                              (Web Push)
```

## Key Features

### REST API Services

Provides backend APIs consumed by the React web application.

Main capabilities include:

- User authentication and account management.
- Security box and user association management.
- Dashboard statistics and monitoring data.
- Transaction history retrieval.
- Fingerprint registration status monitoring.
- User-specific event notification preferences.
- Push notification subscription management.

### IoT Device Communication

Integrates with Azure IoT Hub to support bidirectional communication between the cloud backend and physical security box devices.

**Device-to-Cloud (D2C)**

- Receives device telemetry and event messages through Azure IoT Hub's Event Hub-compatible endpoint.
- Processes security-box events, including door state, fingerprint information, weight and box position.
- Stores relevant device activity and transaction information.
- Triggers real-time notifications when security events occur.

**Cloud-to-Device (C2D)**

- Sends commands from the backend to registered IoT devices.
- Supports fingerprint removal operations.
- Updates related application records following device operations.

### Real-Time Communication

Integrates Azure SignalR Service to distribute device events and application updates to connected web clients.

- Processes IoT events and publishes SignalR messages.
- Supports user-specific connection negotiation.
- Enables real-time dashboard and transaction updates.
- Reduces the need for clients to repeatedly poll backend APIs for new events.

### Push Notifications

Implements browser push notifications using the Web Push protocol.

- Registers and stores browser push subscriptions.
- Manages subscription removal.
- Sends notifications when configured security events occur.
- Uses VAPID credentials for push notification authentication.
- Supports user-specific notification preferences.

### Authentication and Security

- Generates JWT authentication tokens for application sessions.
- Uses BCrypt for password hashing and verification.
- Supports user account and access management.
- Uses application configuration for database and cloud service connection settings.

## Azure Services and Technology Stack

| Category | Technologies |
|---|---|
| Backend | C#, .NET 8, Azure Functions v4 |
| Execution Model | Azure Functions Isolated Worker |
| Database | Azure SQL Database, ADO.NET, SQL Server |
| IoT Integration | Azure IoT Hub, Azure Event Hubs |
| Real-Time Messaging | Azure SignalR Service |
| Push Notifications | Web Push, VAPID |
| Authentication | JWT, BCrypt |
| Monitoring | Azure Application Insights |
| Development | Visual Studio Code, Azure Functions Core Tools |

## Azure Functions

The backend is organised into several function groups.

| Function Group | Responsibilities |
|---|---|
| C2DFunctions | Sends cloud-to-device commands to IoT security boxes. |
| D2CFunctions | Processes incoming IoT messages, handles device events, publishes SignalR messages and sends push notifications. |
| DashboardFunctions | Provides dashboard overview and monitoring data. |
| TransactionFunctions | Retrieves security-box transaction history. |
| UserFunctions | Handles authentication, user management, fingerprint status, event settings, box data and SignalR negotiation. |

## Event Processing Workflow

When an IoT security box generates an event, the backend processes it through the following workflow:

1. The IoT device sends telemetry to Azure IoT Hub.
2. Azure Functions receives the message through an Event Hub trigger.
3. The backend processes the incoming device data.
4. Relevant event and transaction information is stored in Azure SQL Database.
5. SignalR messages are published to connected web clients.
6. Browser push notifications are sent to users where applicable.

## Project Structure

```text
securitybox-azure-functions/
├── Functions/
│   ├── C2DFunctions.cs
│   ├── D2CFunctions.cs
│   ├── DashboardFunctions.cs
│   ├── TransactionFunctions.cs
│   └── UserFunctions.cs
├── Libraries/
│   ├── CommonEnum.cs
│   ├── ConvertDBValue.cs
│   └── Utility.cs
├── Model/
│   └── Entities/
│       ├── EntityClasses.cs
│       ├── PushNotificationObj.cs
│       ├── ResponseObj.cs
│       ├── UserBoxes.cs
│       └── UserEventSettingsDto.cs
├── Properties/
├── Program.cs
├── host.json
└── azure-functions.csproj
```

## Getting Started

### Prerequisites

- .NET 8 SDK
- Azure Functions Core Tools v4
- Visual Studio Code or Visual Studio
- Azure subscription
- Azure SQL Database
- Azure IoT Hub
- Azure SignalR Service

### Installation

Clone the repository:

```bash
git clone <your-repository-url>
```

Navigate to the project directory:

```bash
cd securitybox-azure-functions
```

Restore dependencies:

```bash
dotnet restore
```

### Configuration

Configure the required application settings locally using `local.settings.json` or through Azure Function App application settings.

Required configuration includes:

- Azure Functions runtime settings.
- Azure SQL connection string.
- JWT signing key, issuer and audience.
- Azure SignalR connection string.
- IoT Hub connection strings.
- VAPID public and private keys for push notifications.

**Important:** Never commit `local.settings.json`, connection strings, signing keys or other credentials to source control. Use Azure Function App settings or Azure Key Vault for deployed environments.

### Run Locally

Start the Azure Functions application:

```bash
func start
```

The local Functions host will normally be available at:

```text
http://localhost:7071
```

Some functions also require connectivity to the configured Azure services to operate correctly.

## Learning Outcomes

This project provided practical experience in:

- Developing serverless backend applications using Azure Functions and .NET.
- Integrating cloud services with physical IoT devices through Azure IoT Hub.
- Processing asynchronous device telemetry using Event Hub triggers.
- Implementing bidirectional IoT communication.
- Building REST APIs with C# and ADO.NET.
- Implementing real-time event distribution using Azure SignalR Service.
- Developing browser push notification services.
- Managing authentication using JWT and BCrypt.
- Designing backend workflows for a multi-user, multi-device IoT application.

## Licence

See the [LICENSE](LICENSE) file for licensing information.
