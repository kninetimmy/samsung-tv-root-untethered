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
        if (name.StartsWith("resync-gate-"))
        {
            string gate = name.Substring("resync-gate-".Length);
            bool allowed = DenialRunner.CanResync(gate == "accepted" ? 1 : 0,
                gate == "baseline" ? new DenialRunner.Record() : null,
                gate == "previous" ? new DenialRunner.Record() : null,
                gate == "pre-fence", gate == "post-fence", gate == "invoked",
                gate == "unopened" ? -1 : 42, gate == "unopened" ? -1 : gate == "fd" ? 43 : 42, gate == "used");
            if (allowed != (gate == "good")) throw new Exception("managed capture check failed: " + name + ": resync gate");
            return;
        }
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
        if (name == "post-epipe" || name == "post-einval" || name == "post-errno")
        {
            reads.Clear(); before = false;
            if (!before) { reads.Enqueue(Record(100)); reads.Enqueue(11); }
            reads.Enqueue(name == "post-einval" ? 22 : name == "post-errno" ? 5 : 32);
            reads.Enqueue(Record(101)); reads.Enqueue(11); // a later valid record must not recover EPIPE
            expected = name == "post-einval" ? "kernel-record-oversize" : name == "post-errno" ? "kernel-reader-errno" : "kernel-mid-bracket-overrun-EPIPE";
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
        bool resync = name == "pre-epipe" || name.StartsWith("resync-") || name == "pre-epipe-twice";
        if (resync)
        {
            reads.Clear(); reads.Enqueue(32);
            before = name != "pre-epipe" && name != "resync-good" && name != "resync-post-epipe";
            if (name == "pre-epipe-twice") reads.Enqueue(32);
            if (name == "resync-empty") reads.Enqueue(11);
            if (name == "resync-malformed") reads.Enqueue(Encoding.UTF8.GetBytes("bad\n"));
            if (name == "resync-utf8") reads.Enqueue(new byte[] { 255 });
            if (name == "resync-oversize") reads.Enqueue(new byte[DenialRunner.ReadLimit]);
            reads.Enqueue(Record(100));
            if (name == "resync-gap") reads.Enqueue(Record(102));
            if (name == "resync-no-eagain" || name == "resync-record-bound")
                for (int i = 1; i <= DenialRunner.RecordLimit; i++) reads.Enqueue(Record((ulong)(100 + i)));
            if (name == "resync-byte-bound")
                for (int i = 1; i < 300; i++) reads.Enqueue(Record((ulong)(100 + i), 94000000, new string('x', 4000)));
            reads.Enqueue(11);
            if (name == "resync-post-epipe") reads.Enqueue(32);
            reads.Enqueue(Record(101)); reads.Enqueue(11);
            expected = name == "pre-epipe-twice" ? "kernel-pre-acquisition-EPIPE" :
                name == "resync-post-epipe" ? "kernel-mid-bracket-overrun-EPIPE" :
                name == "resync-empty" ? "kernel-baseline-empty" : name == "resync-gap" ? "kernel-pre-sequence-gap" :
                name == "resync-malformed" ? "kernel-record-malformed-or-unsupported" :
                name == "resync-utf8" ? "kernel-record-decode-incomplete" :
                name == "resync-oversize" ? "kernel-record-oversize-or-empty" :
                name == "resync-byte-bound" ? "kernel-capture-raw-bound" :
                name == "resync-no-eagain" || name == "resync-record-bound" ? "kernel-pre-record-bound" :
                name == "resync-storage" ? "modeled resync persistence failure" :
                name == "resync-time" || name == "resync-time-cumulative" ? "kernel-pre-time-bound" : null;
        }
        if (name == "pre-epipe-baseline")
        {
            reads.Clear(); reads.Enqueue(Record(100)); reads.Enqueue(32); reads.Enqueue(Record(101)); reads.Enqueue(11);
            expected = "kernel-pre-acquisition-EPIPE"; before = true;
        }
        if (name == "pre-final-time" || name == "post-final-time" || name == "pre-record-time" || name == "post-record-time")
        { before = name.StartsWith("pre-"); expected = before ? "kernel-pre-time-bound" : "kernel-post-time-bound"; }
        int opens = 0, closes = 0, attempts = 0, profiles = 0, ticks = 0, consumed = 0;
        int persisted = 0, postTicks = 0;
        long elapsed = 0;
        string durableJson = null;
        bool lastWasEagain = false;
        byte[] lastRead = null;
        Dictionary<string, string> lastProfile = null;
        var output = new StringWriter();
        int code = DenialRunner.Capture(() => { opens++; if (name == "open") throw new Win32Exception(13); return 42; },
            (fd, buffer) => {
                if (fd != 42) throw new Exception("persistent fd changed");
                if (resync && consumed > 0 && persisted != 1)
                    throw new Exception("managed capture check failed: " + name + ": read before durable resync");
                consumed++;
                object next = reads.Dequeue();
                lastWasEagain = next is int againError && againError == 11;
                if (next is int error)
                {
                    if (error == 32 && (name == "resync-time" || name == "resync-time-cumulative")) elapsed = 1500;
                    if (error == 11 && (name == "pre-final-time" && attempts == 0 || name == "post-final-time" && attempts == 1)) elapsed = 2000;
                    throw new DenialRunner.NativeFailure("read", -1, error);
                }
                byte[] data = (byte[])next;
                lastRead = data;
                if (name == "resync-time-cumulative") elapsed = 2100;
                if (name == "pre-record-time" && attempts == 0 || name == "post-record-time" && attempts == 1) elapsed = 2000;
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
            () => { ticks++; if (attempts == 1) postTicks++; return (name == "pre-time" && ticks >= 2) ||
                (name == "post-time" && postTicks >= 2) ? 2000 : elapsed; },
            () => { if (!lastWasEagain) throw new Exception("managed capture check failed: " + name + ": execution before EAGAIN");
                if (resync && persisted != 1) throw new Exception("managed capture check failed: " + name + ": execution before durable resync"); attempts++; throw new Win32Exception(1); }, output,
            json => { persisted++; if (attempts != 0 || consumed != 1 || persisted != 1)
                    throw new Exception("managed capture check failed: " + name + ": resync persistence ordering");
                if (name == "resync-storage") throw new IOException("modeled resync persistence failure");
                durableJson = json;
                if (name == "resync-time") elapsed = 2100; });
        byte[] compressed = Convert.FromBase64String(output.ToString().Trim());
        using (var stream = new GZipStream(new MemoryStream(compressed), CompressionMode.Decompress))
        using (var doc = JsonDocument.Parse(stream))
        {
            var cap = doc.RootElement.GetProperty("kernel_capture");
            string failure = cap.GetProperty("failure").GetString();
            var observed = cap.GetProperty("failure_record");
            bool recordFailure = expected != null && (expected.Contains("bound") && !expected.Contains("time") ||
                expected.Contains("malformed") || expected.Contains("decode") || expected.Contains("oversize-or-empty") ||
                 expected.Contains("sequence") || expected.Contains("timestamp") || expected.Contains("suppressed") ||
                 name.EndsWith("record-time") || name == "resync-time-cumulative");
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
            var resyncEvents = cap.GetProperty("resync_events");
            if (resyncEvents.GetArrayLength() != (resync ? 1 : 0) || persisted != (resync ? 1 : 0) ||
                cap.GetProperty("resync_durable").GetBoolean() != (resync && name != "resync-storage") ||
                (resync && durableJson != null && durableJson != resyncEvents[0].GetRawText()) ||
                cap.GetProperty("same_fd").GetBoolean() != (opens == 1 && name != "open") ||
                cap.GetProperty("execution_invoked").GetBoolean() != (attempts == 1))
                throw new Exception("managed capture check failed: " + name + ": resync/descriptor/provenance accounting");
            if (resync)
            {
                var ev = resyncEvents[0];
                if (ev.GetProperty("errno").GetInt32() != 32 || ev.GetProperty("raw_return").GetInt64() != -1 ||
                    ev.GetProperty("syscall").GetString() != "read" || ev.GetProperty("phase").GetString() != "pre-fence" ||
                    ev.GetProperty("execution_invoked").GetBoolean() || ev.GetProperty("baseline_exists").GetBoolean() ||
                    ev.GetProperty("fence_exists").GetBoolean() || ev.GetProperty("pre_records").GetInt32() != 0 ||
                    ev.GetProperty("pre_bytes").GetInt32() != 0 || ev.GetProperty("fd").GetInt32() != 42)
                    throw new Exception("managed capture check failed: " + name + ": resync evidence");
            }
            if (expected != null && (expected.Contains("EPIPE") || name == "open" || name == "post-errno" || name == "post-einval" || name == "close"))
            {
                var op = cap.GetProperty("failure_operation");
                if (op.ValueKind != JsonValueKind.Object ||
                    op.GetProperty("syscall").GetString() != (name == "open" ? "open" : name == "close" ? "close" : "read") ||
                    op.GetProperty("raw_return").GetInt64() != -1 ||
                    op.GetProperty("phase").GetString() != (before ? "pre-fence" : "post-fence") ||
                    op.GetProperty("execution_invoked").GetBoolean() != (attempts == 1))
                    throw new Exception("managed capture check failed: " + name + ": failing syscall provenance");
            }
            int expectedReads = name == "pre-epipe-baseline" || name == "pre-epipe-twice" ? 2 : name == "post-epipe" ? 3 : name == "resync-post-epipe" ? 4 : -1;
            if (attempts != (before ? 0 : 1) || opens > 1 || closes != opens - (name == "open" ? 1 : 0) ||
                failure != expected || cap.GetProperty("capture_complete").GetBoolean() != (expected == null) ||
                code != (expected == null ? 77 : 79) || (expectedReads >= 0 && consumed != expectedReads))
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
            "post-cap-drift", "post-smack-drift", "pre-epipe-twice", "pre-epipe-baseline",
            "resync-good", "resync-post-epipe", "resync-empty", "resync-gap", "resync-malformed", "resync-utf8",
            "resync-oversize", "resync-byte-bound", "resync-record-bound", "resync-no-eagain", "resync-storage",
            "resync-time", "resync-time-cumulative", "pre-final-time", "post-final-time", "pre-record-time", "post-record-time",
            "resync-gate-good", "resync-gate-accepted", "resync-gate-baseline", "resync-gate-previous", "resync-gate-pre-fence",
            "resync-gate-post-fence", "resync-gate-invoked", "resync-gate-unopened", "resync-gate-fd", "resync-gate-used" };
        foreach (string name in captures) { CaptureCase(name); passed++; }
        Console.WriteLine(JsonSerializer.Serialize(new { passed, failed = 0, skipped = 0, capture_cases = captures }));
        return 0;
    }
}
