using System;
using System.Runtime.InteropServices;

internal static class LaunchContextSelfTest
{
    private static void Require(bool value, string message)
    {
        if (!value) throw new Exception(message);
    }

    public static void Main()
    {
        bool controlReceived = false;
        int starts = 0;
        Action fallback = LaunchContext.CreateIdleFallback(() => controlReceived, () => starts++);
        IntPtr callback = Marshal.GetFunctionPointerForDelegate(fallback);
        var invoke = Marshal.GetDelegateForFunctionPointer<Action>(callback);
        invoke();
        Require(starts == 1, "native idle callback must open diagnostics without launch context");
        controlReceived = true;
        invoke();
        Require(starts == 1, "received context must prevent the native idle fallback from opening UI");
        GC.KeepAlive(fallback);

        const string automaticCaller = "com.samsung.tv.ghdaemon";
        const string defaultOperation = "http://tizen.org/appcontrol/operation/default";
        Require(LaunchContext.ShouldStayQuiet(automaticCaller, defaultOperation, true),
            "the observed healthy automatic repeat must stay quiet");
        Require(!LaunchContext.ShouldStayQuiet(automaticCaller, defaultOperation, false),
            "first boot, missing proof or an unavailable bridge must keep diagnostics visible");
        Require(!LaunchContext.ShouldStayQuiet(null, defaultOperation, true),
            "the observed intentional SDK launch must show the manager");
        Require(!LaunchContext.ShouldStayQuiet("org.tizen.launcher", defaultOperation, true),
            "a launcher request must not be mistaken for the daemon");
        Require(!LaunchContext.ShouldStayQuiet(automaticCaller, "http://tizen.org/appcontrol/operation/main", true),
            "other daemon operations must retain their existing UI behavior");
        Require(!LaunchContext.ShouldStayQuiet(null, null, true),
            "missing metadata must keep diagnostics available");
        Require(!LaunchContext.ShouldStayQuiet("", defaultOperation, true),
            "an empty caller must not select the automatic path");
        Require(!LaunchContext.ShouldStayQuiet(automaticCaller.ToUpperInvariant(), defaultOperation, true),
            "caller identity must match exactly");
        Require(!LaunchContext.ShouldStayQuiet(automaticCaller, defaultOperation + "/extra", true),
            "operation identity must match exactly");

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
        Console.WriteLine("PASS: native idle callback, quiet-launch policy and bounded logging checks (no TV required)");
    }
}
