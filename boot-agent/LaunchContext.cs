using System;
using System.Text;

internal static class LaunchContext
{
    public static bool ShouldStayQuiet(string caller, string operation, bool rootAndBridgeReady)
    {
        return rootAndBridgeReady
            && string.Equals(caller, "com.samsung.tv.ghdaemon", StringComparison.Ordinal)
            && string.Equals(operation, "http://tizen.org/appcontrol/operation/default", StringComparison.Ordinal);
    }

    public static string Describe(string caller, string operation)
    {
        return "launch-control: caller=" + Field(caller) + " operation=" + Field(operation);
    }

    private static string Field(string value)
    {
        if (value == null) return "<unavailable>";
        var result = new StringBuilder("\"");
        int length = Math.Min(value.Length, 256);
        for (int i = 0; i < length; i++)
        {
            char c = value[i];
            if (c == '"' || c == '\\') result.Append('\\').Append(c);
            else if (char.IsControl(c) || c == '\u2028' || c == '\u2029')
                result.Append("\\u").Append(((int)c).ToString("x4"));
            else result.Append(c);
        }
        if (value.Length > length) result.Append("...");
        return result.Append('"').ToString();
    }
}
