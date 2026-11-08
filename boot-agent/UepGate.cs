using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// L4 (task 25): opt-in reapplication of the QN90B UEP enforcement clear after
// boot-root. The kernel's packaged default reloads the enforcement flag at
// every boot, so a manually cleared flag never survives a reboot; when
// /opt/usr/share/selfroot/uep-off.conf exists, the manager runs this gate
// after root proof and re-clears the flag with the same compare-before-write
// CAS that the one-use L2 packet proved live on build T-PTMAKUC-REL-202602250225.
//
// Fail-closed structure:
//   - config absent:              no TV-state change, ever (default enforcing);
//   - config unreadable/unknown:  fail closed, no action;
//   - "read-only":                fingerprint read only, zero stores;
//   - "active":                   at most two guarded clears and one guarded
//                                 restore per boot; every store is a
//                                 compare-before-write with the observed
//                                 page neighbourhood pinned, and never has a
//                                 fallback address (the older-candidate page
//                                 read-faults fatally on this build — L1).
// Every anomaly fails closed: a store happens only while the exact enforcing
// fingerprint is observable immediately before it, the guarded restore fires
// only from a freshly observed cleared state, and a refusal consumes the
// budget attempt (no retries). Boot id rotation resets the per-boot budget;
// a corrupt budget or unreadable boot id disables stores until corrected.
// This code is verified against its self-test only; it has never run against
// a television, and deployment and TV validation remain separately approved.
internal sealed class UepGate
{
    public const string ProductionConfigPath = "/opt/usr/share/selfroot/uep-off.conf";
    public const string ProductionStatePath = "/opt/usr/share/selfroot/uep-state.conf";
    public const string ProductionProbePath = "/opt/usr/share/selfroot/fdetprobe/FdetProbe.dll";
    public const string ProductionRuntimeConfigPath = "/opt/usr/share/selfroot/fdetprobe/FdetProbe.runtimeconfig.json";
    public const string ProductionDotNetPath = "/usr/bin/dotnet";
    public const string ProductionBootIdPath = "/proc/sys/kernel/random/boot_id";

    // Exact byte hashes validated live in the spent L2 packet (never replayed).
    public const string ProductionProbeSha256 = "2cfec6d19ab3ddcc7eb5ec4fe0cb511bf45864994cf990daf2e1ea722b88a8bb";
    public const string ProductionRuntimeConfigSha256 = "2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b";

    private const string TargetPhysical = "0x208c26c0";
    private const int TargetWordOffset = 1;    // page-relative, as FdetProbe wwi expects
    private const int NeighbourWords = 24;
    private const uint EnforcingWord0 = 0xc07bd300u;
    private const uint NeighbourWord3 = 0x000004e2u;
    private const uint ClearedValue = 0u;
    private const uint EnforcingValue = 1u;
    private const int ClearBudget = 2;         // boot-start clear plus one rearm response
    private const int RestoreBudget = 1;       // anomaly recovery only
    private const int ProbeTimeoutMilliseconds = 8000;

    private static readonly uint[] EnforcingWords = { EnforcingWord0, EnforcingValue, 0u, NeighbourWord3 };
    private static readonly uint[] ClearedWords = { EnforcingWord0, ClearedValue, 0u, NeighbourWord3 };

    private readonly string ConfigPath;
    private readonly string StatePath;
    private readonly string ProbePath;
    private readonly string RuntimeConfigPath;
    private readonly string DotNetPath;
    private readonly string BootIdPath;
    private readonly string ExpectedProbeSha256;
    private readonly string ExpectedRuntimeConfigSha256;
    private readonly ProbeRunner RunProbe;
    private readonly Action<string> Log;

    public delegate ProcessResult ProbeRunner(string[] arguments);

    public sealed class ProcessResult
    {
        public int ExitCode;
        public bool Completed;
        public string StdOut;
        public string StdErr;
    }

    private enum ConfigMode
    {
        Absent,
        ReadOnly,
        Active,
        Invalid,
        Unreadable,
    }

    private sealed class Budget
    {
        public string BootId;
        public int Clears;
        public int Restores;
    }

    public UepGate(string configPath, string statePath, string probePath, string runtimeConfigPath,
        string dotNetPath, string bootIdPath, string expectedProbeSha256, string expectedRuntimeConfigSha256,
        ProbeRunner runProbe, Action<string> log)
    {
        ConfigPath = configPath;
        StatePath = statePath;
        ProbePath = probePath;
        RuntimeConfigPath = runtimeConfigPath;
        DotNetPath = dotNetPath;
        BootIdPath = bootIdPath;
        ExpectedProbeSha256 = expectedProbeSha256;
        ExpectedRuntimeConfigSha256 = expectedRuntimeConfigSha256;
        RunProbe = runProbe;
        Log = log ?? delegate { };
    }

    // Runs one gate attempt. Never throws; the caller adds its own safety net.
    // Returns a one-line summary for the manager log.
    public string Run(string phase)
    {
        ConfigMode config;
        string configError;
        try { config = ReadConfig(out configError); }
        catch (Exception)
        {
            return "fail closed (config error)";
        }

        if (config == ConfigMode.Absent)
        {
            return "config absent (enforcing; no action)";
        }

        if (config == ConfigMode.Invalid)
        {
            Log("unexpected config" + configError + " - fail closed (no action)");
            return "unexpected config (fail closed)";
        }

        if (config == ConfigMode.Unreadable)
        {
            Log("config unreadable (" + configError + ") - fail closed (no action)");
            return "config unreadable (fail closed)";
        }

        string payloadError = ValidatePayload();
        if (payloadError != null)
        {
            Log("payload check failed: " + payloadError + " - fail closed (no action)");
            return "payload check failed (fail closed)";
        }

        Budget budget;
        try { budget = LoadBudget(); }
        catch (Exception)
        {
            Log("budget state error - fail closed (no store)");
            return "budget state error (fail closed)";
        }

        if (budget == null)
        {
            Log("corrupt or foreign budget state - fail closed (no store)");
            return "corrupt budget state (fail closed)";
        }

        uint[] words = ReadState();
        if (words == null)
        {
            Log("fingerprint read failed - fail closed (no store)");
            return "fingerprint read failed (fail closed)";
        }

        string classification = Classify(words);
        if (config == ConfigMode.ReadOnly)
        {
            Log("read-only " + phase + ": " + classification + " " + Fingerprint(words) + " (zero stores)");
            return "read-only: " + classification;
        }

        if (classification == "cleared")
        {
            Log("already cleared " + Fingerprint(words) + " (idle, zero stores)");
            return "already cleared (idle)";
        }

        if (classification != "enforcing")
        {
            Log("unexpected fingerprint " + Fingerprint(words) + " " + phase + " - fail closed (no store)");
            return "unexpected fingerprint (fail closed)";
        }

        if (budget.Clears >= ClearBudget)
        {
            Log("clear budget exhausted for boot " + budget.BootId + " (" + budget.Clears + " used) - no store");
            return "clear budget exhausted (fail closed)";
        }

        budget.Clears += 1;
        if (!SaveBudget(budget))
        {
            Log("budget state unwritable - fail closed (no store)");
            return "budget unwritable (fail closed)";
        }

        string[] clearArguments = BuildWwiArguments(EnforcingValue, ClearedValue, words);
        ProcessResult clear = RunProbeGuarded(clearArguments);

        uint[] before;
        uint[] after;
        if (clear != null && clear.Completed && clear.ExitCode == 0
            && TryParseDumpWords(clear.StdOut, out before, out after))
        {
            if (WordsEqual(before, words)
                && ChangedExactlyOneWord(before, after, TargetWordOffset, EnforcingValue, ClearedValue))
            {
                Log("cleared " + phase + ": " + Fingerprint(after) + " (one word, neighbourhood pinned)");
                return "cleared (" + phase + ")";
            }

            Log("clear receipt mismatch (single-change rule) - checked restore follows");
        }
        else
        {
            Log("clear " + DescribeProcessResult(clear) + " - state re-check follows");
        }

        // Anomaly path: one bounded restore, only from a freshly observed
        // cleared state. When the state is still enforcing the clear simply
        // did not take; the remaining boot budget stays reserved for a later
        // same-boot rearm response (no immediate retry).
        uint[] fresh = ReadState();
        if (fresh == null)
        {
            Log("post-clear state unreadable - no restore (fail closed)");
            return "state unreadable after clear (fail closed)";
        }

        if (Classify(fresh) != "cleared")
        {
            Log("clear did not take: " + Fingerprint(fresh) + " - left enforcing (next relaunch re-checks)");
            return "clear did not take (fail closed)";
        }

        if (budget.Restores >= RestoreBudget)
        {
            Log("restore budget exhausted for boot " + budget.BootId + " - no restore (fail closed)");
            return "restore budget exhausted (fail closed)";
        }

        budget.Restores += 1;
        if (!SaveBudget(budget))
        {
            Log("budget unwritable after anomaly - no restore (fail closed)");
            return "budget unwritable after anomaly (fail closed)";
        }

        string[] restoreArguments = BuildWwiArguments(ClearedValue, EnforcingValue, fresh);
        ProcessResult restore = RunProbeGuarded(restoreArguments);
        if (restore != null && restore.Completed && restore.ExitCode == 0
            && TryParseDumpWords(restore.StdOut, out before, out after)
            && WordsEqual(before, fresh)
            && ChangedExactlyOneWord(before, after, TargetWordOffset, ClearedValue, EnforcingValue)
            && HeadMatches(after, EnforcingWords))
        {
            Log("restored after anomaly: " + Fingerprint(after));
            return "restored to enforcing";
        }

        Log("restore " + DescribeProcessResult(restore) + " - final state unverified (fail closed)");
        return "restore unconfirmed (fail closed)";
    }

    private static string DescribeProcessResult(ProcessResult result)
    {
        if (result == null)
        {
            return "could not run";
        }

        return result.Completed ? "exit=" + result.ExitCode : "timed out";
    }

    private static string Classify(uint[] words)
    {
        if (HeadMatches(words, EnforcingWords))
        {
            return "enforcing";
        }

        if (HeadMatches(words, ClearedWords))
        {
            return "cleared";
        }

        return "unexpected";
    }

    private static bool HeadMatches(uint[] words, uint[] expected)
    {
        return words.Length >= expected.Length && WordsEqual(Slice(words, expected.Length), expected);
    }

    private static uint[] Slice(uint[] words, int count)
    {
        uint[] result = new uint[count];
        Array.Copy(words, result, count);
        return result;
    }

    private static bool WordsEqual(uint[] first, uint[] second)
    {
        if (first == null || second == null || first.Length != second.Length)
        {
            return false;
        }

        for (int index = 0; index < first.Length; index++)
        {
            if (first[index] != second[index])
            {
                return false;
            }
        }

        return true;
    }

    private static bool ChangedExactlyOneWord(uint[] before, uint[] after, int offset, uint from, uint to)
    {
        if (before == null || after == null || before.Length != after.Length
            || offset < 0 || offset >= before.Length)
        {
            return false;
        }

        if (before[offset] != from || after[offset] != to)
        {
            return false;
        }

        for (int index = 0; index < before.Length; index++)
        {
            if (index != offset && before[index] != after[index])
            {
                return false;
            }
        }

        return true;
    }

    private static string Fingerprint(uint[] words)
    {
        var builder = new StringBuilder();
        for (int index = 0; index < 4 && index < words.Length; index++)
        {
            if (index > 0)
            {
                builder.Append(" ");
            }

            builder.Append(FormatWord(words[index]));
        }

        return builder.ToString();
    }

    private static string FormatWord(uint value)
    {
        return value.ToString("x8", CultureInfo.InvariantCulture);
    }

    // Neighbour pin: every page word except the target offset, pinned to the
    // observed value, so FdetProbe refuses the store unless the recorded
    // neighbourhood still matches immediately before it.
    private static string[] BuildWwiArguments(uint from, uint to, uint[] observed)
    {
        var builder = new StringBuilder();
        for (int offset = 0; offset < observed.Length; offset++)
        {
            if (offset == TargetWordOffset)
            {
                continue;
            }

            if (builder.Length > 0)
            {
                builder.Append(",");
            }

            builder.Append(offset + ":" + FormatWord(observed[offset]));
        }

        return new[]
        {
            "wwi",
            TargetPhysical,
            TargetWordOffset.ToString(CultureInfo.InvariantCulture),
            FormatWord(from),
            FormatWord(to),
            builder.ToString(),
        };
    }

    private static bool TryParseDumpWords(string stdout, out uint[] before, out uint[] after)
    {
        uint[] parsedBefore;
        uint[] parsedAfter;
        if (TryParseWords(stdout, "words_before", NeighbourWords, out parsedBefore)
            && TryParseWords(stdout, "words_after", NeighbourWords, out parsedAfter))
        {
            before = parsedBefore;
            after = parsedAfter;
            return true;
        }

        before = null;
        after = null;
        return false;
    }

    // Mirrors FdetProbe's PrintMappedWords format: "<label> word=N" lines,
    // eight space-separated x8 words each, contiguous line offsets from 0.
    private static bool TryParseWords(string stdout, string label, int expectedCount, out uint[] words)
    {
        words = new uint[expectedCount];
        int parsed = 0;
        bool found = false;
        foreach (string line in SplitLines(stdout))
        {
            string[] columns = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length < 2 || columns[0] != label)
            {
                continue;
            }

            int offset;
            if (!TryParseWordOffset(columns, out offset) || offset != parsed)
            {
                return false;
            }

            found = true;
            int values = columns.Length - 2;
            if (parsed + values > expectedCount)
            {
                return false;
            }

            for (int index = 0; index < values; index++)
            {
                words[parsed + index] = ParseWord(columns[index + 2]);
            }

            parsed += values;
        }

        return found && parsed == expectedCount;
    }

    private static IEnumerable<string> SplitLines(string stdout)
    {
        if (stdout == null)
        {
            return new string[0];
        }

        return stdout.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
    }

    private static bool TryParseWordOffset(string[] columns, out int offset)
    {
        for (int index = 1; index < columns.Length; index++)
        {
            if (columns[index].StartsWith("word=", StringComparison.Ordinal))
            {
                return int.TryParse(columns[index].Substring(5), NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out offset);
            }
        }

        offset = -1;
        return false;
    }

    private static uint ParseWord(string text)
    {
        // PrintMappedWords always emits lowercase x8 hex tokens; a 0x prefix
        // is tolerated for robustness but never a decimal form.
        string digits = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? text.Substring(2)
            : text;
        return uint.Parse(digits, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    }

    private uint[] ReadState()
    {
        string[] arguments =
        {
            "rw",
            TargetPhysical,
            NeighbourWords.ToString(CultureInfo.InvariantCulture),
        };

        ProcessResult read;
        try { read = RunProbe(arguments); }
        catch (Exception)
        {
            return null;
        }

        if (read == null || !read.Completed || read.ExitCode != 0)
        {
            return null;
        }

        uint[] words;
        return TryParseWords(read.StdOut, "words", NeighbourWords, out words) ? words : null;
    }

    private ConfigMode ReadConfig(out string reason)
    {
        reason = "";
        if (!File.Exists(ConfigPath))
        {
            return ConfigMode.Absent;
        }

        string content;
        try { content = File.ReadAllText(ConfigPath); }
        catch (UnauthorizedAccessException e) { reason = Describe(e); return ConfigMode.Unreadable; }
        catch (IOException e) { reason = Describe(e); return ConfigMode.Unreadable; }

        string text = (content ?? "").Trim().ToLowerInvariant();
        if (text == "active")
        {
            return ConfigMode.Active;
        }

        if (text == "read-only" || text == "readonly")
        {
            return ConfigMode.ReadOnly;
        }

        reason = text.Length == 0 ? " (empty)" : " content";
        return ConfigMode.Invalid;
    }

    private string ValidatePayload()
    {
        if (!File.Exists(DotNetPath))
        {
            return "dotnet missing (" + DotNetPath + ")";
        }

        if (!File.Exists(ProbePath) || !File.Exists(RuntimeConfigPath))
        {
            return "probe files missing";
        }

        string probeSha;
        string runtimeSha;
        try
        {
            probeSha = FileSha256(ProbePath);
            runtimeSha = FileSha256(RuntimeConfigPath);
        }
        catch (UnauthorizedAccessException)
        {
            return "probe files unreadable";
        }
        catch (IOException)
        {
            return "probe files unreadable";
        }

        if (probeSha != ExpectedProbeSha256 || runtimeSha != ExpectedRuntimeConfigSha256)
        {
            return "probe hash mismatch (probe " + probeSha + " runtime " + runtimeSha + ")";
        }

        return null;
    }

    private static string FileSha256(string path)
    {
        using (var sha = SHA256.Create())
        using (var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            byte[] digest = sha.ComputeHash(stream);
            var builder = new StringBuilder(digest.Length * 2);
            foreach (byte value in digest)
            {
                builder.Append(value.ToString("x2", CultureInfo.InvariantCulture));
            }

            return builder.ToString();
        }
    }

    private static string Describe(Exception e)
    {
        return e.GetType().Name + " " + Compress(e.Message);
    }

    private static string Compress(string message)
    {
        if (message == null)
        {
            return "";
        }

        string flat = message.Replace("\r", " ").Replace("\n", " ");
        return flat.Length <= 120 ? flat : flat.Substring(0, 120);
    }

    private Budget LoadBudget()
    {
        string bootId = ReadBootId();
        if (bootId == null)
        {
            return null;
        }

        if (!File.Exists(StatePath))
        {
            return new Budget { BootId = bootId, Clears = 0, Restores = 0 };
        }

        string content;
        try { content = File.ReadAllText(StatePath); }
        catch (UnauthorizedAccessException) { return null; }
        catch (IOException) { return null; }

        string[] tokens = (content ?? "").Trim().Split(' ');
        if (tokens.Length != 3 || !tokens[0].StartsWith("boot=", StringComparison.Ordinal)
            || !tokens[1].StartsWith("clear=", StringComparison.Ordinal)
            || !tokens[2].StartsWith("restore=", StringComparison.Ordinal))
        {
            return null;
        }

        string stateBootId = tokens[0].Substring(5);
        if (stateBootId != bootId)
        {
            return new Budget { BootId = bootId, Clears = 0, Restores = 0 };
        }

        int clears;
        int restores;
        if (!int.TryParse(tokens[1].Substring(6), NumberStyles.Integer, CultureInfo.InvariantCulture, out clears)
            || !int.TryParse(tokens[2].Substring(8), NumberStyles.Integer, CultureInfo.InvariantCulture, out restores)
            || clears < 0 || restores < 0 || clears > ClearBudget || restores > RestoreBudget)
        {
            return null;
        }

        return new Budget { BootId = bootId, Clears = clears, Restores = restores };
    }

    private string ReadBootId()
    {
        try
        {
            string trimmed = (File.ReadAllText(BootIdPath) ?? "").Trim();
            if (trimmed.Length == 0 || trimmed.Length > 64)
            {
                return null;
            }

            foreach (char value in trimmed)
            {
                bool hexish = (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')
                    || (value >= 'A' && value <= 'F') || value == '-';
                if (!hexish)
                {
                    return null;
                }
            }

            return trimmed;
        }
        catch (UnauthorizedAccessException) { return null; }
        catch (IOException) { return null; }
    }

    private bool SaveBudget(Budget budget)
    {
        string content = "boot=" + budget.BootId + " clear=" + budget.Clears
            + " restore=" + budget.Restores + "\n";
        string tempPath = StatePath + ".tmp";
        try
        {
            File.WriteAllText(tempPath, content);
            if (File.Exists(StatePath))
            {
                File.Delete(StatePath);
            }

            File.Move(tempPath, StatePath);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            try { File.Delete(tempPath); } catch { }
            return false;
        }
        catch (IOException)
        {
            try { File.Delete(tempPath); } catch { }
            return false;
        }
    }

    private ProcessResult RunProbeGuarded(string[] arguments)
    {
        try { return RunProbe(arguments); }
        catch (Exception)
        {
            return null;
        }
    }

    // Production probe runner: argument-list based exec of the hash-pinned
    // FdetProbe payload under the system dotnet. The probe prints a bounded
    // dump (a handful of short lines); the timeout replaces the packets' 8s
    // shell watchdog and yields an uncompleted result (no receipt parsing).
    public static ProcessResult RunProductionProbe(string[] arguments)
    {
        var process = new Process();
        var start = process.StartInfo;
        start.FileName = ProductionDotNetPath;
        start.ArgumentList.Add(ProductionProbePath);
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        start.UseShellExecute = false;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        start.CreateNoWindow = true;

        bool completed;
        try
        {
            process.Start();
        }
        catch (Exception)
        {
            return new ProcessResult { ExitCode = -1, Completed = false, StdOut = "", StdErr = "could not start" };
        }

        System.Threading.Tasks.Task<string> outTask = process.StandardOutput.ReadToEndAsync();
        System.Threading.Tasks.Task<string> errorTask = process.StandardError.ReadToEndAsync();
        try
        {
            completed = process.WaitForExit(ProbeTimeoutMilliseconds);
            if (!completed)
            {
                try { process.Kill(); } catch { }
                process.WaitForExit(2000);
            }
        }
        catch (Exception)
        {
            completed = false;
        }

        if (!completed)
        {
            return new ProcessResult { ExitCode = -1, Completed = false, StdOut = "", StdErr = "timed out" };
        }

        string stdOut;
        string stdErr;
        try
        {
            outTask.Wait(1000);
            errorTask.Wait(1000);
            stdOut = outTask.Status == System.Threading.Tasks.TaskStatus.RanToCompletion ? outTask.Result : "";
            stdErr = errorTask.Status == System.Threading.Tasks.TaskStatus.RanToCompletion ? errorTask.Result : "";
        }
        catch (Exception)
        {
            stdOut = "";
            stdErr = "";
        }

        return new ProcessResult
        {
            ExitCode = process.ExitCode,
            Completed = true,
            StdOut = stdOut,
            StdErr = stdErr,
        };
    }
}
