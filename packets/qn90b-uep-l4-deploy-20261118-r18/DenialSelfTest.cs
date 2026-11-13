using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;

public static class DenialSelfTest
{
    public static int Main()
    {
        int passed = 0;
        foreach (int errno in new int[] { 1, 13, 2, 8 })
        {
            var output = new StringWriter();
            int calls = 0;
            int code = DenialRunner.Attempt(() => { calls++; throw new Win32Exception(errno); }, output);
            using (var doc = JsonDocument.Parse(output.ToString()))
            {
                var root = doc.RootElement;
                if (calls != 1 || code != 77 || root.GetProperty("exec_started").GetBoolean() ||
                    root.GetProperty("errno").GetInt32() != errno ||
                    root.GetProperty("native_exit").ValueKind != JsonValueKind.Null)
                    throw new Exception("refused-before-exec accounting failed: " + errno);
            }
            passed++;
        }
        // Exercise the real owned-process exit/output branch on this Windows host.
        var started = new StringWriter();
        int result = DenialRunner.Attempt(() => Process.Start(new ProcessStartInfo {
            FileName = Environment.GetEnvironmentVariable("ComSpec"),
            Arguments = "/d /c echo QN90B_UEP_NATIVE_PROBE_OK & exit /b 42",
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true
        }), started);
        using (var doc = JsonDocument.Parse(started.ToString()))
        {
            var root = doc.RootElement;
            if (result != 78 || !root.GetProperty("exec_started").GetBoolean() ||
                root.GetProperty("native_exit").GetInt32() != 42 ||
                !root.GetProperty("stdout").GetString().Contains("QN90B_UEP_NATIVE_PROBE_OK"))
                throw new Exception("started-child accounting failed");
        }
        passed++;
        var refused = new StringWriter();
        string missing = Path.Combine(Path.GetTempPath(), "r16-missing-" + Guid.NewGuid().ToString("N") + ".exe");
        int refusal = DenialRunner.Attempt(() => Process.Start(new ProcessStartInfo {
            FileName = missing, UseShellExecute = false,
            RedirectStandardOutput = true, RedirectStandardError = true
        }), refused);
        using (var doc = JsonDocument.Parse(refused.ToString()))
        {
            var root = doc.RootElement;
            if (refusal != 77 || root.GetProperty("exec_started").GetBoolean() ||
                root.GetProperty("native_exit").ValueKind != JsonValueKind.Null ||
                root.GetProperty("errno").GetInt32() != 2)
                throw new Exception("real refused-before-exec accounting failed");
        }
        passed++;
        var timeout = new StringWriter();
        int timed = DenialRunner.Attempt(() => Process.Start(new ProcessStartInfo {
            FileName = Environment.GetEnvironmentVariable("ComSpec"),
            Arguments = "/d /c for /l %i in (1,1,2147483647) do @rem",
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true
        }), timeout);
        using (var doc = JsonDocument.Parse(timeout.ToString()))
        {
            if (timed != 78 || !doc.RootElement.GetProperty("timed_out").GetBoolean())
                throw new Exception("owned child timeout/reap failed");
        }
        passed++;
        Console.WriteLine("{\"passed\":" + passed + ",\"failed\":0,\"skipped\":0}");
        return 0;
    }
}
