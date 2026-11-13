using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

public static class DenialSelfTest
{
    static Dictionary<string, string> Profile()
    {
        return new Dictionary<string, string> {
            ["Uid"] = "901 901 901 901", ["Gid"] = "901 901 901 901", ["Groups"] = "901 1901",
            ["CapEff"] = "0000000000200040", ["smack"] = "User", ["dmesg_restrict"] = "0",
            ["boot"] = "299d6f3f-c014-43e5-a487-59c47c833f6f"
        };
    }

    static byte[] Record(ulong sequence, ulong timestamp = 94000000, string message = "noise")
    {
        return Encoding.UTF8.GetBytes("6," + sequence + "," + timestamp + ",-;" + message + "\n");
    }

    static ulong Bytes(Queue<object> reads, int bytes, ulong sequence)
    {
        while (bytes > 0)
        {
            int size = Math.Min(bytes, 4000);
            if (bytes - size > 0 && bytes - size < 100) size -= 100;
            reads.Enqueue(Record(sequence, 94000000, new string('x', size - Record(sequence, 94000000, "").Length)));
            bytes -= size;
            sequence++;
        }
        return sequence;
    }

    public static void CaptureCase(string name)
    {
        var reads = new Queue<object>();
        reads.Enqueue(Record(100)); reads.Enqueue(11); reads.Enqueue(Record(101, 95000000)); reads.Enqueue(11);
        string expected = null;
        bool before = false;
        if (name == "pre-empty") { reads.Clear(); reads.Enqueue(11); reads.Enqueue(Record(101, 95000000)); reads.Enqueue(11); expected = "kernel-baseline-empty"; before = true; }
        if (name == "open") { expected = "kernel-reader-errno"; before = true; }
        if (name == "restrict" || name == "identity" || name == "group" || name == "smack" || name == "boot")
        {
            expected = new Dictionary<string, string> { ["restrict"] = "kernel-access-dmesg-restrict-drift",
                ["identity"] = "kernel-access-helper-identity-drift", ["group"] = "kernel-access-owning-group-drift",
                ["smack"] = "kernel-access-smack-drift", ["boot"] = "kernel-boot-drift" }[name];
            before = true;
        }
        var profileChanges = new Dictionary<string, string[]> {
            ["uid"] = new[] { "Uid", "901 901 0 901", "kernel-access-helper-identity-drift" },
            ["gid"] = new[] { "Gid", "901 901 901 0", "kernel-access-helper-identity-drift" },
            ["zero-cap"] = new[] { "CapEff", "0000000000000000", "kernel-access-helper-identity-drift" },
            ["system-label"] = new[] { "smack", "System", "kernel-access-smack-drift" },
            ["post-cap-drift"] = new[] { "CapEff", "0000000000000000", "kernel-access-helper-identity-drift" },
            ["post-smack-drift"] = new[] { "smack", "System", "kernel-access-smack-drift" }
        };
        if (profileChanges.TryGetValue(name, out string[] changedProfile))
        {
            expected = changedProfile[2]; before = !name.StartsWith("post-");
        }
        if (name == "pre-epipe" || name == "post-epipe" || name == "post-einval" || name == "post-errno")
        {
            reads.Clear(); before = name == "pre-epipe";
            if (!before) { reads.Enqueue(Record(100)); reads.Enqueue(11); }
            reads.Enqueue(name == "post-einval" ? 22 : name == "post-errno" ? 5 : 32);
            reads.Enqueue(Record(101)); reads.Enqueue(11); // a later valid record must not recover EPIPE
            expected = name == "post-einval" ? "kernel-record-oversize" : name == "post-errno" ? "kernel-reader-errno" : "kernel-overrun-EPIPE";
        }
        if (name == "baseline-gap" || name == "middle-gap" || name == "pre-gap" || name == "post-order" || name == "pre-order" || name == "suppression" || name.EndsWith("malformed") || name.EndsWith("oversize") || name == "flags" || name == "dictionary" || name == "priority" || name.EndsWith("utf8"))
        {
            reads.Clear(); reads.Enqueue(Record(100));
            before = name.StartsWith("pre-");
            if (!before) reads.Enqueue(11);
            if (name == "middle-gap") reads.Enqueue(Record(101, 95000000));
            if (name.EndsWith("malformed")) reads.Enqueue(Encoding.UTF8.GetBytes("bad\n"));
            else if (name.EndsWith("utf8")) reads.Enqueue(new byte[] { 255 });
            else if (name == "flags") reads.Enqueue(Encoding.UTF8.GetBytes("6,101,95000000,c;noise\n"));
            else if (name == "dictionary") reads.Enqueue(Encoding.UTF8.GetBytes("6,101,95000000,-;noise\n KEY=value\n"));
            else if (name == "priority") reads.Enqueue(Encoding.UTF8.GetBytes("192,101,95000000,-;noise\n"));
            else if (name.EndsWith("oversize")) reads.Enqueue(new byte[DenialRunner.ReadLimit]);
            else reads.Enqueue(Record(name == "middle-gap" ? 103UL : name.Contains("gap") ? 102UL : 101UL,
                name.Contains("order") ? 93000000UL : 95000000UL,
                name == "suppression" ? "2 callbacks suppressed" : "noise"));
            reads.Enqueue(11);
            expected = name == "pre-gap" ? "kernel-pre-sequence-gap" : name == "baseline-gap" ? "kernel-sequence-gap: expected=101 observed=102" :
                name == "middle-gap" ? "kernel-sequence-gap: expected=102 observed=103" :
                name.Contains("order") ? "kernel-timestamp-reversal" : name == "suppression" ? "kernel-emission-suppressed" :
                name.EndsWith("oversize") ? "kernel-record-oversize-or-empty" : name.EndsWith("utf8") ? "kernel-record-decode-incomplete" : "kernel-record-malformed-or-unsupported";
            if (before) { reads.Enqueue(Record(name == "pre-order" ? 102UL : 103UL, 96000000)); reads.Enqueue(11); }
        }
        if (name == "pre-record-bound" || name == "post-record-bound" || name == "pre-byte-bound" || name == "post-byte-bound")
        {
            reads.Clear(); before = name.StartsWith("pre-");
            if (!before) { reads.Enqueue(Record(100)); reads.Enqueue(11); }
            int count = name.Contains("record") ? DenialRunner.RecordLimit + 1 : 300;
            string message = name.Contains("record") ? "n" : new string('x', 4000);
            for (int i = 0; i < count; i++) reads.Enqueue(Record((ulong)(101 + i), 95000000, message));
            reads.Enqueue(11);
            if (before) { reads.Enqueue(Record((ulong)(101 + count), 95000000)); reads.Enqueue(11); }
            expected = name.Contains("byte") ? "kernel-capture-raw-bound" : before ? "kernel-pre-record-bound" : "kernel-post-record-bound";
        }
        if (name == "raw-exact" || name == "raw-combined-over")
        {
            reads.Clear();
            ulong next = Bytes(reads, 700000, 1);
            reads.Enqueue(11);
            Bytes(reads, DenialRunner.ByteLimit - 700000 + (name == "raw-combined-over" ? 1 : 0), next);
            reads.Enqueue(11);
            if (name == "raw-combined-over") expected = "kernel-capture-raw-bound";
        }
        if (name == "pre-time" || name == "post-time") { before = name == "pre-time"; expected = before ? "kernel-pre-time-bound" : "kernel-post-time-bound"; }
        if (name == "close") expected = "kernel-close-errno";
        if (name == "profile-drift") expected = "kernel-access-profile-drift";
        int opens = 0, closes = 0, attempts = 0, profiles = 0, ticks = 0, consumed = 0;
        byte[] lastRead = null;
        Dictionary<string, string> lastProfile = null;
        var output = new StringWriter();
        int code = DenialRunner.Capture(() => { opens++; if (name == "open") throw new Win32Exception(13); return 42; },
            (fd, buffer) => {
                if (fd != 42) throw new Exception("persistent fd changed");
                consumed++;
                object next = reads.Dequeue();
                if (next is int error) throw new Win32Exception(error);
                byte[] data = (byte[])next;
                lastRead = data;
                Array.Copy(data, buffer, data.Length); return data.Length;
            }, fd => { if (fd != 42) throw new Exception("closed different fd"); closes++; if (name == "close") throw new Win32Exception(5); },
            () => { var profile = Profile(); profiles++;
                if (name == "restrict") profile["dmesg_restrict"] = "1";
                if (name == "identity") profile["CapEff"] = "0000000000200000";
                if (name == "group") profile["Groups"] = "901";
                if (name == "smack") profile["smack"] = "_";
                if (name == "boot") profile["boot"] = "wrong";
                if (name == "profile-drift" && profiles == 2) profile["NoNewPrivs"] = "1";
                if (changedProfile != null && (before || profiles == 2)) profile[changedProfile[0]] = changedProfile[1];
                lastProfile = profile;
                return profile; },
            () => { ticks++; return (name == "pre-time" && ticks >= 2) || (name == "post-time" && attempts == 1 && ticks >= 5) ? 2000 : 0; },
            () => { attempts++; throw new Win32Exception(1); }, output);
        byte[] compressed = Convert.FromBase64String(output.ToString().Trim());
        using (var stream = new GZipStream(new MemoryStream(compressed), CompressionMode.Decompress))
        using (var doc = JsonDocument.Parse(stream))
        {
            var cap = doc.RootElement.GetProperty("kernel_capture");
            string failure = cap.GetProperty("failure").GetString();
            var observed = cap.GetProperty("failure_record");
            bool recordFailure = expected != null && (expected.Contains("bound") && !expected.Contains("time") ||
                expected.Contains("malformed") || expected.Contains("decode") || expected.Contains("oversize-or-empty") ||
                expected.Contains("sequence") || expected.Contains("timestamp") || expected.Contains("suppressed"));
            if (recordFailure)
            {
                if (observed.ValueKind == JsonValueKind.Null || observed.GetProperty("phase").GetString() != (before ? "pre" : "post") ||
                    observed.GetProperty("count").GetInt32() != lastRead.Length ||
                    observed.GetProperty("retained_bytes").GetInt32() != lastRead.Length ||
                    observed.GetProperty("truncated").GetBoolean() ||
                    observed.GetProperty("raw_b64").GetString() != Convert.ToBase64String(lastRead))
                    throw new Exception("managed capture check failed: " + name + ": offending observation lost");
            }
            else if (observed.ValueKind != JsonValueKind.Null)
                throw new Exception("managed capture check failed: " + name + ": stale offending observation");
            var postProfile = cap.GetProperty("post_profile");
            if (profiles == 2)
            {
                if (postProfile.ValueKind == JsonValueKind.Null || JsonSerializer.Serialize(lastProfile) != postProfile.GetRawText())
                    throw new Exception("managed capture check failed: " + name + ": post-profile observation lost");
            }
            else if (postProfile.ValueKind != JsonValueKind.Null)
                throw new Exception("managed capture check failed: " + name + ": invented post-profile");
            if (attempts != (before ? 0 : 1) || opens > 1 || closes != opens - (name == "open" ? 1 : 0) ||
                failure != expected || cap.GetProperty("capture_complete").GetBoolean() != (expected == null) ||
                code != (expected == null ? 77 : 79) || (name.Contains("epipe") && consumed != (before ? 1 : 3)))
                throw new Exception("managed capture check failed: " + name + ": " + failure);
        }
    }

    public static int Main(string[] args)
    {
        if (args.Length == 1) { CaptureCase(args[0]); return 0; }
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
        string[] captures = { "good", "pre-empty", "open", "restrict", "identity", "group", "smack", "boot",
            "pre-epipe", "post-epipe", "post-einval", "post-errno", "baseline-gap", "middle-gap", "pre-gap",
            "post-order", "pre-order", "suppression", "malformed", "oversize", "pre-record-bound", "post-record-bound",
            "pre-byte-bound", "post-byte-bound", "pre-time", "post-time", "close", "profile-drift",
            "flags", "dictionary", "priority", "raw-exact", "raw-combined-over", "utf8",
            "pre-malformed", "pre-utf8", "pre-oversize", "uid", "gid", "zero-cap", "system-label",
            "post-cap-drift", "post-smack-drift" };
        foreach (string name in captures) { CaptureCase(name); passed++; }
        Console.WriteLine(JsonSerializer.Serialize(new { passed, failed = 0, skipped = 0, capture_cases = captures }));
        return 0;
    }
}
