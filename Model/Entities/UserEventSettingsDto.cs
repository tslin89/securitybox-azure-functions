public class UserEventSettings
{
    public string EventCode { get; set; }
    public string EventDescription { get; set; }
    public int EventType { get; set; }
    public bool? NotificationEnabled { get; set; } = true;
}