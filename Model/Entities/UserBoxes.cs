using System.Security.Cryptography;

public class UserBoxes
{
    public int UserID { get; set; }
    public long BoxID { get; set; }
    public int UserRole { get; set; }
    public long? FingerprintNum { get; set; }
}