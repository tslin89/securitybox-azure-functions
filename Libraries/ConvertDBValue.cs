using System.Data.SqlClient;

namespace SecurityBoxFunctions.Library;

public static class ConvertDBValue
{
    public static int ReadInt32(SqlDataReader reader, string fieldName)
    {
        return reader.IsDBNull(reader.GetOrdinal(fieldName)) ? 0 : Convert.ToInt32(reader.GetValue(reader.GetOrdinal(fieldName)));
    }

    public static long ReadInt64(SqlDataReader reader, string fieldName)
    {
        return reader.IsDBNull(reader.GetOrdinal(fieldName)) ? 0 : Convert.ToInt64(reader.GetValue(reader.GetOrdinal(fieldName)));
    }

    public static bool ReadBit(SqlDataReader reader, string fieldName)
    {
        return reader.IsDBNull(reader.GetOrdinal(fieldName)) ? false : Convert.ToBoolean(reader.GetValue(reader.GetOrdinal(fieldName)));
    }

    public static string ReadString(SqlDataReader reader, string fieldName)
    {
        return reader.IsDBNull(reader.GetOrdinal(fieldName)) ? "" : Convert.ToString(reader.GetValue(reader.GetOrdinal(fieldName)));
    }

    public static DateTime? ReadDateTime(SqlDataReader reader, string fieldName)
    {
        return reader.IsDBNull(reader.GetOrdinal(fieldName)) ? null : reader.GetDateTime(reader.GetOrdinal(fieldName));
    }

    public static float? ReadFloat(SqlDataReader reader, string fieldName)
    {
        return reader.IsDBNull(reader.GetOrdinal(fieldName)) ? null : Convert.ToSingle(reader.GetValue(reader.GetOrdinal(fieldName)));
    }

    public static long ToInt64(object number)
    {
        Int64.TryParse(number == null ? "" : Convert.ToString(number), out long result);
        return result;
    }

    public static long ToInt32(object number)
    {
        Int32.TryParse(number == null ? "" : Convert.ToString(number), out int result);
        return result;
    }
}