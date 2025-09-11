using System;

namespace azure_functions.Model.Entities;

public class EntityClasses
{

}

public class IoTDeviceData
{
    public DateTime TimeStamp { get; set; }
    public long BoxID { get; set; }
    public string EventCode { get; set; }
    public int? DoorState { get; set; }
    public int? FingerprintNum { get; set; }
    public float? TotalWeight { get; set; }
    public long? BoxPosition { get; set; }
}