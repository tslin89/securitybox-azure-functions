using System;
using System.Collections.Generic;

namespace SecurityBoxFunctions.Model.Entities
{
    public class SecurityBoxData
    {
        public int Id { get; set; }
        public DateTime TimeStamp { get; set; }
        public long BoxID { get; set; }
        public string EventCode { get; set; }
        public long? DoorState { get; set; }
        public long? FingerprintNum { get; set; }
        public float? TotalWeight { get; set; }
        public long? BoxPosition { get; set; }
        public long? UserID { get; set; }
        public string? TransactionID { get; set; }
        public DateTime? ReceivedTime { get; set; }
    }

    public class UserBoxData : SecurityBoxData
    {
        public string DeviceID { get; set; }
        public string BoxDescription { get; set; }
        public DateTime? TimeStamp { get; set; }
        public long? UserFingerprintNum { get; set; }
        public long? UserID { get; set; }
    }

    public sealed class LoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public sealed class Users
    {
        public int UserID { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string PhoneNo { get; set; }
        public long BoxID { get; set; }
        public bool FingerprintEnabled { get; set; }
        public int UserType { get; set; }
    }

    public sealed class IotSignal
    {
        public int BoxID { get; set; }
        public string? EventCode { get; set; }
        public int DoorState { get; set; }
        public int FingerprintNum { get; set; }
        public double TotalWeight { get; set; }
        public int BoxPosition { get; set; }
    }
}