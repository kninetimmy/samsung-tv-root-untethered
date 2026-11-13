using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

// Direct Process.Start reports execve errno separately from a child's exit.
// No shell, native fallback, execution retries, gate writes or reboot API.
public static class DenialRunner
{
    public const int ReadLimit = 8192, RecordLimit = 16384, ByteLimit = 1048576;
    public const int OpenFlags = 2048; // Linux O_RDONLY | O_NONBLOCK; no reopen/seek/write.
    public const string ExpectedCapEff = "0000000000200040", ExpectedSmack = "User";
    [DllImport("libc", SetLastError = true, EntryPoint = "open")]
    static extern int Open(string path, int flags);
    [DllImport("libc", SetLastError = true, EntryPoint = "read")]
    static extern IntPtr Read(int fd, byte[] buffer, UIntPtr count);
    [DllImport("libc", SetLastError = true, EntryPoint = "close")]
    static extern int Close(int fd);
    [DllImport("libc", SetLastError = true, EntryPoint = "fsync")]
    static extern int Fsync(int fd);

    public sealed class NativeFailure : Win32Exception
    {
        public readonly string operation;
        public readonly long rawReturn;
        public NativeFailure(string operation, long rawReturn, int errno) : base(errno)
        { this.operation = operation; this.rawReturn = rawReturn; }
    }

    public static object Provenance(string operation, long? rawReturn, string phase, bool invoked)
    { return new { syscall = operation, raw_return = rawReturn, phase, execution_invoked = invoked }; }

    public static bool CanResync(int accepted, Record baseline, Record previous, bool preFence,
        bool postFence, bool invoked, int fd, int openedFd, bool used)
    {
        return accepted == 0 && baseline == null && previous == null && !preFence && !postFence &&
            !invoked && fd >= 0 && fd == openedFd && !used;
    }

    public static void PersistResync(string directory, string json)
    {
        // Exclusive creation refuses an existing file/symlink. File and parent must
        // both reach stable storage before the next read, let alone Process.Start.
        using (var stream = new FileStream(Path.Combine(directory, "DenialRunner.resync.json"),
            FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            byte[] raw = Encoding.UTF8.GetBytes(json + "\n");
            stream.Write(raw, 0, raw.Length);
            stream.Flush(true);
        }
        int fd = Open(directory, 65536); // O_RDONLY | O_DIRECTORY, no seek/reopen of kmsg.
        if (fd < 0) throw new NativeFailure("open-resync-directory", fd, Marshal.GetLastWin32Error());
        try
        {
            int result = Fsync(fd);
            if (result != 0) throw new NativeFailure("fsync-resync-directory", result, Marshal.GetLastWin32Error());
        }
        finally
        {
            int result = Close(fd);
            if (result != 0) throw new NativeFailure("close-resync-directory", result, Marshal.GetLastWin32Error());
        }
    }

    public sealed class Record
    {
        public ulong sequence, timestamp;
        public string raw;
    }

    public static Record Parse(byte[] buffer, int count)
    {
        if (count <= 0 || count >= ReadLimit) throw new InvalidDataException("kernel-record-oversize-or-empty");
        string raw = new UTF8Encoding(false, true).GetString(buffer, 0, count);
        var match = Regex.Match(raw, @"\A([0-9]{1,3}),([0-9]{1,20}),([0-9]{1,20}),-;([^\r\n\x00]*)\n\z");
        if (!match.Success || !int.TryParse(match.Groups[1].Value, out int priority) || priority > 191 ||
            !ulong.TryParse(match.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out ulong sequence) ||
            !ulong.TryParse(match.Groups[3].Value, NumberStyles.None, CultureInfo.InvariantCulture, out ulong timestamp))
            throw new InvalidDataException("kernel-record-malformed-or-unsupported");
        return new Record { raw = Convert.ToBase64String(buffer, 0, count), sequence = sequence, timestamp = timestamp };
    }

    public static bool Suppressed(string text)
    {
        return Regex.IsMatch(text, @"(?i)(callbacks? suppressed|messages? suppressed|messages? dropped|dropped [0-9]+|[0-9]+ messages? lost|printk.*(?:suppress|drop|lost)|ratelimit)");
    }

    public static Dictionary<string, string> Profile()
    {
        var profile = new Dictionary<string, string>();
        foreach (string line in File.ReadAllLines("/proc/self/status"))
        {
            int colon = line.IndexOf(':');
            if (colon < 0) continue;
            string key = line.Substring(0, colon);
            if (key == "Uid" || key == "Gid" || key == "Groups" || key.StartsWith("Cap") || key == "NoNewPrivs")
                profile[key] = line.Substring(colon + 1).Trim();
        }
        profile["smack"] = File.ReadAllText("/proc/self/attr/current").TrimEnd('\n', '\0');
        profile["boot"] = File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim();
        profile["dmesg_restrict"] = File.ReadAllText("/proc/sys/kernel/dmesg_restrict").Trim();
        return profile;
    }

    public static void ValidateProfile(Dictionary<string, string> profile)
    {
        if (profile["dmesg_restrict"] != "0") throw new InvalidDataException("kernel-access-dmesg-restrict-drift");
        if (!Regex.IsMatch(profile["Uid"], @"\A901\s+901\s+901\s+901\z") ||
            !Regex.IsMatch(profile["Gid"], @"\A901\s+901\s+901\s+901\z") ||
            profile["CapEff"] != ExpectedCapEff)
            throw new InvalidDataException("kernel-access-helper-identity-drift");
        if (!Regex.IsMatch(profile["Groups"], @"(?:\A|\s)1901(?:\s|\z)"))
            throw new InvalidDataException("kernel-access-owning-group-drift");
        if (profile["smack"] != ExpectedSmack) throw new InvalidDataException("kernel-access-smack-drift");
        if (profile["boot"] != "299d6f3f-c014-43e5-a487-59c47c833f6f")
            throw new InvalidDataException("kernel-boot-drift");
    }

    // Injected transcripts exercise these same drains on Windows; they do not prove Linux ABI semantics.
    public static object Observation(string phase, byte[] buffer, int count)
    {
        int retained = Math.Min(Math.Max(count, 0), ReadLimit);
        return new { phase, count, retained_bytes = retained, truncated = count != retained,
            raw_b64 = Convert.ToBase64String(buffer, 0, retained) };
    }

    public static int Capture(Func<int> open, Func<int, byte[], int> read, Action<int> close,
        Func<Dictionary<string, string>> profileRead, Func<long> milliseconds,
        Func<Process> start, TextWriter output, Action<string> persistResync)
    {
        int fd = -1, code = 79, errno = 0, preCount = 0, preBytes = 0, postBytes = 0;
        bool preFence = false, postFence = false, complete = false, executionInvoked = false;
        bool resyncUsed = false, resyncDurable = false;
        int openedFd = -1;
        string phase = "pre-fence", operation = null;
        long? rawReturn = null;
        object failureOperation = null;
        var resyncEvents = new List<object>();
        string failure = null;
        Record baseline = null, previous = null;
        var records = new List<string>();
        Dictionary<string, string> profile = null, postProfile = null;
        object failureRecord = null;
        JsonElement? exec = null;
        try
        {
            profile = profileRead();
            ValidateProfile(profile);
            var buffer = new byte[ReadLimit];
            long begun = milliseconds();
            operation = "open";
            fd = open();
            openedFd = fd;
            operation = null;
            while (true)
            {
                if (milliseconds() - begun >= 2000) throw new InvalidDataException("kernel-pre-time-bound");
                int count;
                bool again = false;
                operation = "read";
                try { count = read(fd, buffer); rawReturn = count; }
                catch (Win32Exception error) when (error.NativeErrorCode == 11) { count = 0; rawReturn = -1; again = true; }
                catch (Win32Exception error) when (error.NativeErrorCode == 32 &&
                    CanResync(preCount, baseline, previous, preFence, postFence, executionInvoked, fd, openedFd, resyncUsed))
                {
                    rawReturn = error is NativeFailure failedRead ? failedRead.rawReturn : -1;
                    if (milliseconds() - begun >= 2000) throw new InvalidDataException("kernel-pre-time-bound");
                    resyncUsed = true;
                    var ev = new { syscall = "read", raw_return = error is NativeFailure native ? native.rawReturn : -1,
                        phase, execution_invoked = executionInvoked, errno = error.NativeErrorCode, fd,
                        pre_records = preCount, pre_bytes = preBytes, baseline_exists = baseline != null,
                        fence_exists = preFence || postFence, elapsed_ms = milliseconds() - begun };
                    resyncEvents.Add(ev);
                    operation = "persist-resync"; rawReturn = null;
                    persistResync(JsonSerializer.Serialize(ev)); // failure is fatal; budgets/continuity never reset
                    resyncDurable = true;
                    if (milliseconds() - begun >= 2000) throw new InvalidDataException("kernel-pre-time-bound");
                    operation = null;
                    continue;
                }
                operation = null;
                if (!again) failureRecord = Observation("pre", buffer, count);
                if (milliseconds() - begun >= 2000) throw new InvalidDataException("kernel-pre-time-bound");
                if (again) { preFence = true; break; }
                failureRecord = Observation("pre", buffer, count);
                preCount++;
                preBytes += count;
                if (preCount > RecordLimit) throw new InvalidDataException("kernel-pre-record-bound");
                if (preBytes > ByteLimit) throw new InvalidDataException("kernel-capture-raw-bound");
                Record record = Parse(buffer, count);
                if (previous != null && (previous.sequence == ulong.MaxValue || record.sequence != previous.sequence + 1))
                    throw new InvalidDataException("kernel-pre-sequence-gap");
                if (previous != null && record.timestamp < previous.timestamp) throw new InvalidDataException("kernel-timestamp-reversal");
                previous = baseline = record;
                failureRecord = null;
            }
            if (baseline == null) throw new InvalidDataException("kernel-baseline-empty");
            var result = new StringWriter();
            executionInvoked = true;
            phase = "post-fence";
            code = Attempt(start, result); // exactly one direct denial attempt; never retry, even after read failure
            using (var doc = JsonDocument.Parse(result.ToString())) exec = doc.RootElement.Clone();
            begun = milliseconds();
            while (true)
            {
                if (milliseconds() - begun >= 2000) throw new InvalidDataException("kernel-post-time-bound");
                int count;
                bool again = false;
                operation = "read";
                try { count = read(fd, buffer); rawReturn = count; }
                catch (Win32Exception error) when (error.NativeErrorCode == 11) { count = 0; rawReturn = -1; again = true; }
                operation = null;
                if (!again) failureRecord = Observation("post", buffer, count);
                if (milliseconds() - begun >= 2000) throw new InvalidDataException("kernel-post-time-bound");
                if (again) { postFence = true; break; }
                failureRecord = Observation("post", buffer, count);
                postBytes += count;
                if (records.Count >= RecordLimit) throw new InvalidDataException("kernel-post-record-bound");
                if (preBytes + postBytes > ByteLimit) throw new InvalidDataException("kernel-capture-raw-bound");
                // Retain the raw framing before validating it, including malformed/oversize input.
                if (count > 0 && count <= buffer.Length) records.Add(Convert.ToBase64String(buffer, 0, count));
                Record record = Parse(buffer, count);
                if (previous.sequence == ulong.MaxValue || record.sequence != previous.sequence + 1)
                    throw new InvalidDataException("kernel-sequence-gap: expected=" + (previous.sequence + 1) + " observed=" + record.sequence);
                if (record.timestamp < previous.timestamp) throw new InvalidDataException("kernel-timestamp-reversal");
                if (Suppressed(Encoding.UTF8.GetString(buffer, 0, count))) throw new InvalidDataException("kernel-emission-suppressed");
                previous = record;
                failureRecord = null;
            }
            postProfile = profileRead();
            if (FileProfileChanged(profile, postProfile)) throw new InvalidDataException("kernel-access-profile-drift");
            complete = true;
        }
        catch (Win32Exception error)
        {
            errno = error.NativeErrorCode;
            failureOperation = Provenance(error is NativeFailure native ? native.operation : operation,
                error is NativeFailure rawFailure ? rawFailure.rawReturn : -1, phase, executionInvoked);
            failure = errno == 32 ? (phase == "pre-fence" ? "kernel-pre-acquisition-EPIPE" : "kernel-mid-bracket-overrun-EPIPE") : errno == 22 ? "kernel-record-oversize" : "kernel-reader-errno";
        }
        catch (Exception error) when (error is IOException || error is InvalidDataException ||
            error is DecoderFallbackException || error is FormatException || error is KeyNotFoundException || error is TimeoutException)
        {
            failure = error is DecoderFallbackException ? "kernel-record-decode-incomplete" : error.Message;
            failureOperation = Provenance(operation, operation == null ? null : rawReturn, phase, executionInvoked);
        }
        finally
        {
            if (fd >= 0)
            {
                try { close(fd); }
                catch (Win32Exception error) { errno = error.NativeErrorCode; failure = "kernel-close-errno"; complete = false;
                    failureOperation = Provenance("close", error is NativeFailure native ? native.rawReturn : -1, phase, executionInvoked); }
            }
        }
        var envelope = new { version = 1, exec, kernel_capture = new {
            capture_complete = complete, capacity_state = "unknown", profile, post_profile = postProfile,
            failure_record = failureRecord, // bounded diagnostic only, never completeness authority
            pre_eagain = preFence, post_eagain = postFence, same_fd = fd >= 0 && fd == openedFd,
            execution_invoked = executionInvoked, failure_operation = failureOperation,
            resync_events = resyncEvents, resync_durable = resyncDurable,
            baseline = baseline == null ? null : baseline.raw, records,
            pre_records = preCount, pre_bytes = preBytes, post_bytes = postBytes,
            errno, failure
        }};
        byte[] raw = JsonSerializer.SerializeToUtf8Bytes(envelope);
        using (var stream = new MemoryStream())
        {
            using (var gzip = new GZipStream(stream, CompressionLevel.Optimal, true)) gzip.Write(raw, 0, raw.Length);
            output.WriteLine(Convert.ToBase64String(stream.ToArray()));
        }
        return complete ? code : 79;
    }

    static bool FileProfileChanged(Dictionary<string, string> before, Dictionary<string, string> after)
    {
        ValidateProfile(after);
        foreach (var field in before) if (!after.TryGetValue(field.Key, out string value) || field.Value != value) return true;
        return before.Count != after.Count;
    }

    public static int Attempt(Func<Process> start, TextWriter output)
    {
        Process child;
        try { child = start(); }
        catch (Win32Exception error)
        {
            output.WriteLine(JsonSerializer.Serialize(new {
                exec_started = false, errno = error.NativeErrorCode,
                native_exit = (int?)null, timed_out = false, stdout = "", stderr = ""
            }));
            return 77; // refusal, never a successful native child exit
        }
        if (child == null) throw new InvalidOperationException("Process.Start returned null");
        using (child)
        {
            var stdout = child.StandardOutput.ReadToEndAsync();
            var stderr = child.StandardError.ReadToEndAsync();
            bool completed = child.WaitForExit(5000);
            if (!completed)
            {
                child.Kill(); // this Process handle, never a shell/PID lookup
                if (!child.WaitForExit(1000)) throw new TimeoutException("owned child did not exit after kill");
            }
            if (!System.Threading.Tasks.Task.WaitAll(new System.Threading.Tasks.Task[] { stdout, stderr }, 1000))
                throw new TimeoutException("owned child output did not close");
            output.WriteLine(JsonSerializer.Serialize(new {
                exec_started = true, errno = (int?)null, native_exit = (int?)child.ExitCode,
                timed_out = !completed, stdout = stdout.Result, stderr = stderr.Result
            }));
            return 78; // ANY started child is failure for this denial control
        }
    }

    public static int Main(string[] args)
    {
        if (args.Length != 1 || !System.Text.RegularExpressions.Regex.IsMatch(args[0],
            @"^/home/owner/share/tmp/sdk_tools/denial-[0-9a-f]{16}/uep-probe\.elf$"))
            throw new ArgumentException("one exact denial staging path required");
        var clock = Stopwatch.StartNew();
        return Capture(() => {
            int fd = Open("/dev/kmsg", OpenFlags);
            if (fd < 0) throw new NativeFailure("open", fd, Marshal.GetLastWin32Error());
            return fd;
        }, (fd, buffer) => {
            long count = Read(fd, buffer, (UIntPtr)buffer.Length).ToInt64();
            if (count < 0) throw new NativeFailure("read", count, Marshal.GetLastWin32Error());
            return checked((int)count);
        }, fd => {
            int result = Close(fd);
            if (result != 0) throw new NativeFailure("close", result, Marshal.GetLastWin32Error());
        }, Profile, () => clock.ElapsedMilliseconds, () => Process.Start(new ProcessStartInfo {
            FileName = args[0], UseShellExecute = false,
            RedirectStandardOutput = true, RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(args[0])
        }), Console.Out, json => PersistResync(Path.GetDirectoryName(args[0]), json));
    }
}
