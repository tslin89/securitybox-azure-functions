namespace SecurityBoxFunctions.Model.Entities;

public sealed class StoredPushSubscription
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Endpoint { get; set; } = "";
    public string P256dh { get; set; } = "";
    public string Auth { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ExpirationTime { get; set; }
}

public sealed class PushSubscribeDto
{
    public int UserId { get; set; }
    public PushSubscriptionDto Subscription { get; set; } = default!;
}

public sealed class PushSubscriptionDto
{
    public string endpoint { get; set; } = "";
    public long? expirationTime { get; set; }
    public PushKeys keys { get; set; } = default!;
}

public sealed class PushKeys
{
    public string p256dh { get; set; } = "";
    public string auth { get; set; } = "";
}