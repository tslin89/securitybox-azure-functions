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
        public int? DoorState { get; set; }
        public int? FingerprintNum { get; set; }
        public float? TotalWeight { get; set; }
        public long? BoxPosition { get; set; }
    }

    public sealed class LoginRequest
    {
        public string? Email { get; set; }
        public string? Password { get; set; }
    }
}