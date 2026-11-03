using System;

internal static class LaunchContextSelfTest
{
    private static void Require(bool value, string message)
    {
        if (!value) throw new Exception(message);
    }

    public static void Main()
    {
        Require(LaunchContext.Describe("org.tizen.launcher", "http://tizen.org/appcontrol/operation/main")
            == "launch-control: caller=\"org.tizen.launcher\" operation=\"http://tizen.org/appcontrol/operation/main\"",
            "caller and operation must remain distinct and readable");
        Require(LaunchContext.Describe(null, null)
            == "launch-control: caller=<unavailable> operation=<unavailable>",
            "missing launch metadata must be explicit");
        Require(LaunchContext.Describe("", "") == "launch-control: caller=\"\" operation=\"\"",
            "empty fields must remain distinct from unavailable metadata");
        Require(LaunchContext.Describe("caller\"\\", "\r\n\t\0\u2028\u2029")
            == "launch-control: caller=\"caller\\\"\\\\\" operation=\"\\u000d\\u000a\\u0009\\u0000\\u2028\\u2029\"",
            "launch fields must not inject log lines or field delimiters");
        Require(LaunchContext.Describe(new string('c', 256), "operation")
            == "launch-control: caller=\"" + new string('c', 256) + "\" operation=\"operation\"",
            "fields at the limit must not be marked as truncated");
        Require(LaunchContext.Describe(new string('c', 257), new string('o', 257))
            == "launch-control: caller=\"" + new string('c', 256) + "...\" operation=\"" + new string('o', 256) + "...\"",
            "both oversized fields must be bounded with visible truncation");

        var controls = "";
        for (int c = 0; c < 160; c++)
            if (char.IsControl((char)c)) controls += (char)c;
        var line = LaunchContext.Describe(controls, controls);
        foreach (char c in line)
            Require(!char.IsControl(c), "all control characters must be escaped");
        Require(LaunchContext.Describe(new string('\0', 10000), new string('\0', 10000)).Length < 3200,
            "escaping must not allow unbounded log records");
        Console.WriteLine("PASS: launch-context field, escaping and size checks (no TV required)");
    }
}
