using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

internal sealed class CutoverGate
{
    private readonly Func<long> clock;
    private readonly bool power;
    private long expires;
    private int phase;
    internal bool WriteAttempted { get; private set; }
    internal bool PowerCommitted { get; private set; }
    internal bool RestoreAttempted { get; private set; }

    internal CutoverGate(bool power, Func<long> clock) { this.power = power; this.clock = clock; }
    private void Check(int expected)
    {
        if (phase != expected || clock() >= expires) throw new InvalidOperationException("cutover phase or expiry mismatch");
    }
    internal void Ready(Action validate, Action publish)
    {
        if (phase != 0) throw new InvalidOperationException("cutover already prepared");
        phase = -1;
        validate();
        expires = clock() + 30000;
        publish();
        phase = 1;
    }
    internal void Switch(Action validateBefore, Action consume, Action write, Action validateAfter, Action publish)
    {
        Check(1);
        phase = -1;
        validateBefore();
        if (clock() >= expires) throw new TimeoutException("IP acknowledgement expired");
        consume();
        if (clock() >= expires) throw new TimeoutException("IP acknowledgement expired before write");
        WriteAttempted = power;
        if (power) write();
        validateAfter();
        if (clock() >= expires) throw new TimeoutException("IP readback expired");
        expires = clock() + 30000;
        publish();
        phase = 2;
    }
    internal NativeRebootResult Commit(Action validate, Action consume, Action sync, Action entry, Func<NativeRebootResult> reboot)
    {
        Check(2);
        PowerCommitted = true; // No automatic restoration after accepting the power acknowledgement.
        phase = 3;
        Action checkedContext = () => { Check(3); validate(); Check(3); };
        RebootGate gate = new RebootGate(power, clock);
        gate.Ready(checkedContext, () => { });
        return gate.Commit(checkedContext, () => { Check(3); consume(); Check(3); },
            () => { Check(3); sync(); Check(3); }, () => { Check(3); entry(); Check(3); }, reboot);
    }
    internal void Restore(Func<bool> alreadyBefore, Action writeBefore, Action verifyBefore)
    {
        if (PowerCommitted) throw new InvalidOperationException("power committed; restoration forbidden");
        phase = -1;
        if (!WriteAttempted) return;
        if (RestoreAttempted) throw new InvalidOperationException("restoration already attempted");
        RestoreAttempted = true;
        if (!alreadyBefore()) writeBefore();
        verifyBefore();
    }
}

internal static class LinuxCutoverHelper
{
    private const string After = "127.0.0.1";
    private static readonly Stopwatch Clock = Stopwatch.StartNew();
    private static Dictionary<string, string> config;
    private static string configPath, configHash, directory, selfHash, snapshot;
    private static bool power;
    private static int writes, restores, syncCalls, rebootCalls;
    private static FileStream status;

    internal static Dictionary<string, string> Fields(string text)
    {
        var result = new Dictionary<string, string>();
        foreach (string line in text.Split('\n'))
        {
            if (line.Length == 0) continue;
            int split = line.IndexOf('=');
            if (split <= 0 || result.ContainsKey(line.Substring(0, split))) throw new InvalidDataException("duplicate or malformed field");
            result.Add(line.Substring(0, split), line.Substring(split + 1).Trim());
        }
        return result;
    }
    internal static void CheckAcknowledgement(string text, string run, string hash, string readyHash)
    {
        var fields = Fields(text);
        if (fields.Count != 3 || fields["run_id"] != run || fields["config_sha256"] != hash || fields["ready_sha256"] != readyHash)
            throw new InvalidDataException("cutover acknowledgement mismatch");
    }
    private static string Capture()
    {
        int tid = int.Parse(File.ReadAllText("/proc/thread-self/stat").Split(' ')[0]);
        using (var resource = typeof(LinuxCutoverHelper).Assembly.GetManifestResourceStream("snapshot.sh"))
        using (var reader = new StreamReader(resource))
            return Run("/bin/bash", "agent=" + getpid() + "\ntid=" + tid + "\n" + reader.ReadToEnd(), "-s");
    }
    private static string Run(string executable, string input, params string[] arguments)
    {
        var start = new ProcessStartInfo(executable) {
            UseShellExecute = false, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        using (Process process = Process.Start(start))
        {
            if (process == null) throw new InvalidOperationException("command did not start");
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (input != null) process.StandardInput.Write(input);
            process.StandardInput.Close();
            if (!process.WaitForExit(12000))
            {
                process.Kill(true);
                process.WaitForExit();
                throw new TimeoutException("cutover command timed out");
            }
            string text = output.GetAwaiter().GetResult();
            if (process.ExitCode != 0 || error.GetAwaiter().GetResult().Length != 0) throw new InvalidOperationException("cutover command failed");
            return text;
        }
    }
    private static void Validate(string ip)
    {
        if (LinuxRebootHelper.Hash(LinuxRebootHelper.ReadOrdinary(configPath, 8192)) != configHash
            || LinuxRebootHelper.Hash(LinuxRebootHelper.ReadOrdinary(Assembly.GetExecutingAssembly().Location, 65536)) != selfHash)
            throw new InvalidOperationException("cutover code/configuration changed");
        snapshot = Capture();
        var expected = new Dictionary<string, string>(config);
        expected["developer_ip"] = ip;
        LinuxRebootHelper.CheckSnapshot(snapshot, expected, getpid());
        IntPtr library;
        if (!NativeLibrary.TryLoad("libc.so.6", out library)) throw new InvalidOperationException("libc unavailable");
        try
        {
            IntPtr symbol;
            if (!NativeLibrary.TryGetExport(library, "sync", out symbol) || !NativeLibrary.TryGetExport(library, "reboot", out symbol))
                throw new InvalidOperationException("native power symbols unavailable");
        }
        finally { NativeLibrary.Free(library); }
    }
    private static bool BeforeRestore()
    {
        // Establish the same boot/context before accepting either of the two known IP values.
        string ip = Fields(Capture())["ip"];
        if (ip == "[system] db/sdk/develop/ip = String: " + config["developer_ip"])
        {
            Validate(config["developer_ip"]);
            return true;
        }
        Validate(After);
        return false;
    }
    private static void SetIp(string ip)
    {
        Run("/usr/bin/buxton2ctl", null, "set-string", "system", "db/sdk/develop/ip", ip);
    }
    private static void Record(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text + "\n");
        status.Write(bytes, 0, bytes.Length);
        status.Flush(power);
    }
    private static string Publish(string name, string phase)
    {
        string text = "run_id=" + config["run_id"] + "\n" + snapshot
            + "phase=" + phase + "\ncode_sha256=" + selfHash + "\nconfig_sha256=" + configHash
            + "\npower_mode=" + config["mode"] + "\nsession_id=" + getsid(0) + "\ngroup_id=" + getpgid(0)
            + "\nsetting_writes=" + writes + "\nrestores=" + restores
            + "\nsync_calls=" + syncCalls + "\nreboot_calls=" + rebootCalls + "\n";
        LinuxRebootHelper.WriteOwned(Path.Combine(directory, name), text, power);
        Record("phase=" + phase);
        return LinuxRebootHelper.Hash(Encoding.UTF8.GetBytes(text));
    }
    private static void WaitForAcknowledgement(string name, string readyHash)
    {
        string path = Path.Combine(directory, name);
        long deadline = Clock.ElapsedMilliseconds + 30000;
        while (!File.Exists(path))
        {
            if (Clock.ElapsedMilliseconds >= deadline) throw new TimeoutException("cutover acknowledgement absent");
            Thread.Sleep(50);
        }
        CheckAcknowledgement(Encoding.UTF8.GetString(LinuxRebootHelper.ReadOrdinary(path, 2048)), config["run_id"], configHash, readyHash);
    }
    private static void Consume(string name)
    {
        LinuxRebootHelper.WriteOwned(Path.Combine(directory, name), "run_id=" + config["run_id"] + "\n", power);
    }
    public static int Main(string[] args)
    {
        CutoverGate gate = null;
        try
        {
            if (args.Length != 3 || (args[0] != "--inspect" && args[0] != "--wait"))
                throw new ArgumentException("usage: LinuxCutoverHelper --inspect|--wait CONFIG SHA256");
            directory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            const string alias = "/home/owner/share/tmp/sdk_tools/";
            const string canonical = "/opt/usr/home/owner/share/tmp/sdk_tools/";
            if (directory.StartsWith(alias, StringComparison.Ordinal)) directory = canonical + directory.Substring(alias.Length);
            if (Path.GetDirectoryName(directory) != canonical.TrimEnd('/') || !Regex.IsMatch(Path.GetFileName(directory), "^archive-root-[0-9a-f]{16}$"))
                throw new InvalidOperationException("cutover helper outside staging root");
            configPath = Path.GetFullPath(args[1]);
            if (configPath.StartsWith(alias, StringComparison.Ordinal)) configPath = canonical + configPath.Substring(alias.Length);
            if (configPath != Path.Combine(directory, "cutover.conf") || !Regex.IsMatch(args[2], "^[0-9a-f]{64}$"))
                throw new InvalidDataException("cutover configuration path/digest mismatch");
            configHash = args[2];
            byte[] bytes = LinuxRebootHelper.ReadOrdinary(configPath, 8192);
            if (LinuxRebootHelper.Hash(bytes) != configHash) throw new InvalidDataException("cutover configuration digest mismatch");
            config = Fields(Encoding.UTF8.GetString(bytes));
            string[] names = { "run_id", "mode", "boot", "developer_ip", "pid_ns", "user_ns", "host_mnt", "code_sha256" };
            if (config.Count != names.Length) throw new InvalidDataException("unexpected configuration fields");
            foreach (string name in names) if (!config.ContainsKey(name)) throw new InvalidDataException("missing configuration field");
            IPAddress desktop;
            Guid boot;
            if (config["run_id"] != Path.GetFileName(directory) || !Guid.TryParseExact(config["boot"], "D", out boot)
                || !IPAddress.TryParse(config["developer_ip"], out desktop) || desktop.AddressFamily != AddressFamily.InterNetwork
                || IPAddress.IsLoopback(desktop) || desktop.Equals(IPAddress.Any) || desktop.Equals(IPAddress.Broadcast)
                || desktop.ToString() != config["developer_ip"] || !Regex.IsMatch(config["code_sha256"], "^[0-9a-f]{64}$"))
                throw new InvalidDataException("invalid cutover identity/IP/hash");
            if (config["mode"] != "rehearse" && config["mode"] != "cutover") throw new InvalidDataException("unknown cutover mode");
            power = config["mode"] == "cutover";
            selfHash = config["code_sha256"];
            Validate(config["developer_ip"]);
            if (args[0] == "--inspect")
            {
                Console.Write(snapshot + "code_sha256=" + selfHash + "\npower_mode=" + config["mode"] + "\nsetting_writes=0\nsync_calls=0\nreboot_calls=0\n");
                return 0;
            }
            if (getsid(0) != getpid() || getpgid(0) != getpid()) throw new InvalidOperationException("cutover helper is not detached");
            status = LinuxRebootHelper.CreateOwned(Path.Combine(directory, "cutover-status.log"));
            Record("run_id=" + config["run_id"]);
            gate = new CutoverGate(power, () => Clock.ElapsedMilliseconds);
            string ready = null;
            gate.Ready(() => Validate(config["developer_ip"]), () => { ready = Publish("cutover-ready", "READY_FOR_IP"); });
            WaitForAcknowledgement("cutover-arm-ip", ready);
            string afterIp = power ? After : config["developer_ip"];
            gate.Switch(() => Validate(config["developer_ip"]), () => Consume("cutover-ip-consumed"),
                () => { writes++; SetIp(After); }, () => Validate(afterIp),
                () => { ready = Publish("cutover-ip-ready", power ? "IP_READBACK_127" : "REHEARSAL_IP_UNCHANGED"); });
            WaitForAcknowledgement("cutover-arm-power", ready);
            NativeRebootResult result = gate.Commit(() => Validate(afterIp), () => Consume("cutover-power-consumed"),
                () => { syncCalls++; Record("phase=SYNC_ENTERED"); sync(); Record("phase=SYNC_RETURNED"); },
                () => Record(power ? "phase=NATIVE_ENTRY_PENDING" : "phase=REHEARSAL_NO_POWER"),
                () => { rebootCalls++; int value = reboot(0x01234567); int errno = Marshal.GetLastWin32Error(); return new NativeRebootResult(value, errno); });
            Record("setting_writes=" + writes + "\nrestores=" + restores + "\nsync_calls=" + syncCalls + "\nreboot_calls=" + rebootCalls);
            if (!power) { Record("phase=REHEARSAL_COMPLETE"); return 0; }
            Record("native_return=" + result.ReturnValue + " errno=" + result.Errno + "\nphase=NATIVE_RETURNED_NO_AUTOMATIC_RESTORE");
            return result.ReturnValue == -1 ? 20 : 21;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.GetType().Name + ": " + error.Message);
            if (gate != null && !gate.PowerCommitted && gate.WriteAttempted)
            {
                try
                {
                    gate.Restore(BeforeRestore, () => { restores++; SetIp(config["developer_ip"]); }, () => Validate(config["developer_ip"]));
                    Record("phase=PRE_POWER_ORIGINAL_IP_VERIFIED");
                }
                catch (Exception restoreError)
                {
                    Console.Error.WriteLine("restoration unverified: " + restoreError.Message);
                    return 51;
                }
            }
            if (status != null) Record("phase=STOPPED\npower_committed=" + (gate != null && gate.PowerCommitted ? "true" : "false")
                + "\nsetting_writes=" + writes + "\nrestores=" + restores + "\nsync_calls=" + syncCalls + "\nreboot_calls=" + rebootCalls);
            return 50;
        }
        finally { if (status != null) status.Dispose(); }
    }
    [DllImport("libc.so.6")] private static extern int getpid();
    [DllImport("libc.so.6")] private static extern int getsid(int pid);
    [DllImport("libc.so.6")] private static extern int getpgid(int pid);
    [DllImport("libc.so.6")] private static extern void sync();
    [DllImport("libc.so.6", SetLastError = true)] private static extern int reboot(int command);
}
