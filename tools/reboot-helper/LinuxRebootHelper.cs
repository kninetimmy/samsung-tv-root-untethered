using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

internal readonly struct NativeRebootResult
{
    internal readonly int ReturnValue;
    internal readonly int Errno;
    internal NativeRebootResult(int value, int errno) { ReturnValue = value; Errno = errno; }
}

internal sealed class RebootGate
{
    private readonly bool power;
    private readonly Func<long> clock;
    private long expires;
    private bool ready;
    private bool used;

    internal RebootGate(bool allowPower, Func<long> monotonicMilliseconds)
    { power = allowPower; clock = monotonicMilliseconds; }

    internal void Ready(Action validate, Action publishReady)
    {
        if (ready || used) throw new InvalidOperationException("readiness already consumed");
        validate();
        publishReady();
        expires = clock() + 30000;
        ready = true;
    }

    private void BeforeEntry()
    {
        if (clock() >= expires) throw new TimeoutException("arming expired before native entry");
    }

    internal NativeRebootResult Commit(Action validate, Action consume, Action sync,
        Action recordEntry, Func<NativeRebootResult> reboot)
    {
        if (!ready || used) throw new InvalidOperationException("commit not ready or already consumed");
        used = true;
        BeforeEntry();
        validate();
        BeforeEntry();
        consume();
        if (power) sync();
        BeforeEntry();
        validate();
        BeforeEntry();
        recordEntry();
        BeforeEntry();
        return power ? reboot() : new NativeRebootResult(0, 0);
    }
}

internal static class LinuxRebootHelper
{
    // Linux/glibc RB_AUTOBOOT, not an architecture-specific raw syscall number.
    private const int Restart = 0x01234567;
    private static readonly Stopwatch Clock = Stopwatch.StartNew();
    private static Dictionary<string, string> config;
    private static string directory;
    private static string configPath;
    private static string configHash;
    private static string selfHash;
    private static bool power;
    private static FileStream status;
    private static string snapshot;
    private static int syncCalls;
    private static int rebootCalls;

    private static string CaptureOwnSnapshot()
    {
        int tid = int.Parse(File.ReadAllText("/proc/thread-self/stat").Split(' ')[0]);
        ProcessStartInfo start = new ProcessStartInfo("/bin/bash");
        start.ArgumentList.Add("-s");
        start.UseShellExecute = false;
        start.RedirectStandardInput = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        using (Process process = Process.Start(start))
        {
            if (process == null) throw new InvalidOperationException("snapshot process did not start");
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            using (var resource = typeof(LinuxRebootHelper).Assembly.GetManifestResourceStream("snapshot.sh"))
            using (var reader = new StreamReader(resource))
                process.StandardInput.Write("agent=" + getpid() + "\ntid=" + tid + "\n" + reader.ReadToEnd());
            process.StandardInput.Close();
            if (!process.WaitForExit(12000))
            {
                process.Kill(true);
                process.WaitForExit();
                throw new TimeoutException("helper snapshot timed out");
            }
            string captured = output.GetAwaiter().GetResult();
            if (process.ExitCode != 0 || error.GetAwaiter().GetResult().Length != 0)
                throw new InvalidOperationException("helper snapshot failed");
            return captured;
        }
    }

    internal static string Hash(byte[] bytes)
    {
        using (SHA256 digest = SHA256.Create())
            return BitConverter.ToString(digest.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
    }

    internal static byte[] ReadOrdinary(string path, int limit)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("redirected helper file");
        using (FileStream file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        using (MemoryStream output = new MemoryStream())
        {
            byte[] chunk = new byte[4096];
            int count;
            while ((count = file.Read(chunk, 0, chunk.Length)) != 0)
            {
                if (output.Length + count > limit) throw new IOException("helper file exceeds limit");
                output.Write(chunk, 0, count);
            }
            return output.ToArray();
        }
    }

    internal static FileStream CreateOwned(string path)
    {
        // CreateNew supplies atomic exclusive creation, including refusal of existing symlinks.
        FileStream file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        int result = fchown(file.SafeFileHandle.DangerousGetHandle().ToInt32(), 901, 901);
        int errno = Marshal.GetLastWin32Error();
        if (result != 0) { file.Dispose(); throw new IOException("new-file fchown errno=" + errno); }
        return file;
    }

    internal static void WriteOwned(string path, string text, bool durable)
    {
        using (FileStream file = CreateOwned(path))
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            file.Write(bytes, 0, bytes.Length);
            file.Flush(durable);
        }
    }

    private static Dictionary<string, string> Fields(string text)
    {
        Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in text.Split('\n'))
        {
            if (line.Length == 0) continue;
            int split = line.IndexOf('=');
            if (split <= 0 || result.ContainsKey(line.Substring(0, split)))
                throw new InvalidDataException("malformed or duplicate helper field");
            result.Add(line.Substring(0, split), line.Substring(split + 1).Trim());
        }
        return result;
    }

    private static void Equal(Dictionary<string, string> data, string key, string expected)
    {
        string value;
        if (!data.TryGetValue(key, out value) || value != expected)
            throw new InvalidOperationException("helper context mismatch: " + key);
    }

    private static void Validate()
    {
        if (Hash(ReadOrdinary(configPath, 8192)) != configHash)
            throw new InvalidOperationException("helper configuration changed");
        if (Hash(ReadOrdinary(Assembly.GetExecutingAssembly().Location, 65536)) != selfHash)
            throw new InvalidOperationException("helper code changed");
        snapshot = CaptureOwnSnapshot();
        foreach (string line in File.ReadAllLines("/proc/meminfo"))
            if (line.StartsWith("Dirty:", StringComparison.Ordinal)
                || line.StartsWith("Writeback:", StringComparison.Ordinal)
                || line.StartsWith("NFS_Unstable:", StringComparison.Ordinal))
                snapshot += "storage_" + line.Substring(0, line.IndexOf(':')).ToLowerInvariant()
                    + "=" + line.Substring(line.IndexOf(':') + 1).Trim() + "\n";
        snapshot += "storage_mounts_base64=" + Convert.ToBase64String(ReadOrdinary("/proc/1/mounts", 12288)) + "\n";
        snapshot += "storage_locks_base64=" + Convert.ToBase64String(ReadOrdinary("/proc/locks", 12288)) + "\n";
        CheckSnapshot(snapshot, config, getpid());
        IntPtr library;
        if (!NativeLibrary.TryLoad("libc.so.6", out library))
            throw new InvalidOperationException("libc.so.6 is unavailable");
        try
        {
            IntPtr symbol;
            if (!NativeLibrary.TryGetExport(library, "reboot", out symbol)
                || !NativeLibrary.TryGetExport(library, "sync", out symbol))
                throw new InvalidOperationException("native power symbols unavailable");
        }
        finally { NativeLibrary.Free(library); }
    }

    internal static void CheckSnapshot(string text, Dictionary<string, string> expected, int actualPid)
    {
        Dictionary<string, string> data = Fields(text);
        Equal(data, "uid", "0 0 0 0");
        Equal(data, "gid", "0 0 0 0");
        Equal(data, "Seccomp", "0");
        Equal(data, "NoNewPrivs", "0");
        Equal(data, "label", "User");
        Equal(data, "boot", expected["boot"]);
        Equal(data, "ip", "[system] db/sdk/develop/ip = String: " + expected["developer_ip"]);
        Equal(data, "mode", "[system] db/sdk/develop/mode = Int32: 1");
        Equal(data, "init_comm", "systemd");
        Equal(data, "init_ppid", "0");
        if (!Regex.IsMatch(data["tid"], "^[1-9][0-9]*$") || data["NSpid"] != data["tid"])
            throw new InvalidOperationException("helper thread is not in the host PID namespace");
        foreach (string ns in new[] { "pid", "user" })
        {
            Equal(data, "caller_" + ns, expected[ns + "_ns"]);
            Equal(data, "init_" + ns, expected[ns + "_ns"]);
        }
        Equal(data, "init_mnt", expected["host_mnt"]);
        if (data["caller_mnt"] == data["init_mnt"])
            throw new InvalidOperationException("expected private mount namespace missing");
        ulong required = (1UL << 22) | 1UL;
        if ((Convert.ToUInt64(data["CapEff"], 16) & required) != required)
            throw new InvalidOperationException("helper CAP_SYS_BOOT/CHOWN missing");
        foreach (string name in new[] { "caller_uid_map", "caller_gid_map", "init_uid_map", "init_gid_map" })
        {
            string[] map = data[name].Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
            if (string.Join(" ", map) != "0 0 4294967295")
                throw new InvalidOperationException("helper identity map mismatch");
        }
        if (actualPid.ToString() != data["agent"])
            throw new InvalidOperationException("helper snapshot is not its own process");
    }

    private static void Record(string message)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(message + "\n");
        status.Write(bytes, 0, bytes.Length);
        status.Flush(power);
    }

    public static int Main(string[] args)
    {
        try
        {
            if (args.Length != 3 || (args[0] != "--inspect" && args[0] != "--wait"))
                throw new ArgumentException("usage: LinuxRebootHelper --inspect|--wait CONFIG SHA256");
            directory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            const string alias = "/home/owner/share/tmp/sdk_tools/";
            const string canonical = "/opt/usr/home/owner/share/tmp/sdk_tools/";
            if (directory.StartsWith(alias, StringComparison.Ordinal))
                directory = canonical + directory.Substring(alias.Length);
            if (Path.GetDirectoryName(directory) != canonical.TrimEnd('/')
                || !Regex.IsMatch(Path.GetFileName(directory), "^archive-root-[0-9a-f]{16}$"))
                throw new InvalidOperationException("helper outside fixed staging root");
            configPath = Path.GetFullPath(args[1]);
            if (configPath.StartsWith(alias, StringComparison.Ordinal))
                configPath = canonical + configPath.Substring(alias.Length);
            if (configPath != Path.Combine(directory, "linux-power.conf"))
                throw new InvalidOperationException("helper configuration path escaped staging");
            configHash = args[2];
            byte[] bytes = ReadOrdinary(configPath, 8192);
            if (Hash(bytes) != configHash) throw new InvalidDataException("helper configuration digest mismatch");
            config = Fields(Encoding.UTF8.GetString(bytes));
            string[] names = { "run_id", "mode", "boot", "developer_ip", "pid_ns", "user_ns", "host_mnt", "code_sha256" };
            if (config.Count != names.Length) throw new InvalidDataException("unexpected helper configuration fields");
            foreach (string name in names) if (!config.ContainsKey(name)) throw new InvalidDataException("missing helper configuration field");
            Equal(config, "run_id", Path.GetFileName(directory));
            if (config["mode"] != "rehearse" && config["mode"] != "reboot")
                throw new InvalidDataException("unknown helper mode");
            power = config["mode"] == "reboot";
            selfHash = config["code_sha256"];
            Validate();
            if (args[0] == "--inspect")
            {
                Console.Write(snapshot);
                Console.WriteLine("code_sha256=" + selfHash);
                Console.WriteLine("power_mode=" + config["mode"]);
                Console.WriteLine("native_symbols=present\nsync_calls=0\nreboot_calls=0");
                return 0;
            }
            if (getsid(0) != getpid() || getpgid(0) != getpid())
                throw new InvalidOperationException("power helper is not detached in its own session/group");
            status = CreateOwned(Path.Combine(directory, "linux-status.log"));
            Record("run_id=" + config["run_id"]);
            RebootGate gate = new RebootGate(power, () => Clock.ElapsedMilliseconds);
            string ready = null;
            gate.Ready(Validate, () => {
                ready = "run_id=" + config["run_id"] + "\n" + snapshot
                    + "code_sha256=" + selfHash + "\npower_mode=" + config["mode"]
                    + "\nsession_id=" + getsid(0) + "\ngroup_id=" + getpgid(0)
                    + "\nsync_calls=0\nreboot_calls=0\n";
                WriteOwned(Path.Combine(directory, "linux-ready"), ready, power);
            });
            string readyHash = Hash(Encoding.UTF8.GetBytes(ready));
            Record("phase=READY");
            string arm = Path.Combine(directory, "linux-arm");
            long armDeadline = Clock.ElapsedMilliseconds + 30000;
            while (!File.Exists(arm))
            {
                if (Clock.ElapsedMilliseconds >= armDeadline)
                    throw new TimeoutException("helper was not armed; no reboot");
                Thread.Sleep(50);
            }
            Dictionary<string, string> arming = Fields(Encoding.UTF8.GetString(ReadOrdinary(arm, 2048)));
            if (arming.Count != 3) throw new InvalidDataException("invalid arm fields");
            Equal(arming, "run_id", config["run_id"]);
            Equal(arming, "config_sha256", configHash);
            Equal(arming, "ready_sha256", readyHash);
            NativeRebootResult returned = gate.Commit(Validate,
                () => WriteOwned(Path.Combine(directory, "linux-consumed"), "run_id=" + config["run_id"] + "\n", power),
                () => { syncCalls++; Record("phase=SYNC_ENTERED"); sync(); Record("phase=SYNC_RETURNED"); },
                () => Record(power ? "phase=NATIVE_ENTRY_PENDING" : "phase=REHEARSAL_NO_POWER"),
                () => {
                    rebootCalls++;
                    int value = reboot(Restart);
                    int errno = Marshal.GetLastWin32Error();
                    return new NativeRebootResult(value, errno);
                });
            Record("sync_calls=" + syncCalls);
            Record("reboot_calls=" + rebootCalls);
            if (!power) { Record("phase=REHEARSAL_COMPLETE"); return 0; }
            Record("native_return=" + returned.ReturnValue + " errno=" + returned.Errno);
            Record("phase=NATIVE_RETURNED_NOT_REBOOT_PROOF");
            return returned.ReturnValue == -1 ? 20 : 21;
        }
        catch (Exception error)
        {
            string message = error.GetType().Name + ": " + error.Message;
            Console.Error.WriteLine(message);
            if (status != null) Record("error=" + message);
            return 50;
        }
        finally { if (status != null) status.Dispose(); }
    }

    [DllImport("libc.so.6", SetLastError = true)] private static extern int fchown(int fd, uint uid, uint gid);
    [DllImport("libc.so.6")] private static extern int getpid();
    [DllImport("libc.so.6")] private static extern int getsid(int pid);
    [DllImport("libc.so.6")] private static extern int getpgid(int pid);
    [DllImport("libc.so.6")] private static extern void sync();
    [DllImport("libc.so.6", SetLastError = true)] private static extern int reboot(int command);
}
