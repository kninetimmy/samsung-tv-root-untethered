using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

// Host-only contract test for the v5.19 root-context gate host. The gate's own
// fail-closed matrix lives in UepGateSelfTest.cs and still covers the shared
// UepGate.cs unchanged; this test pins the host layer only: which configs it
// accepts, that absent/invalid configs never invoke the probe, that a
// read-only config performs exactly one read and zero stores, that the active
// path reports a clear, and that an unexpected probe failure still exits 0
// (a boot module must never look like a boot failure).
internal static class UepGateHostSelfTest
{
    private static void Require(bool value, string message)
    {
        if (!value) throw new Exception(message);
    }

    // Same 24-word page neighbourhood the gate self-test pins (L2 receipt).
    private static readonly uint[] Enforcing24 =
    {
        0xc07bd300u, 1u, 0u, 0x4e2u, 0xau, 0u, 0u, 0u,
        0u, 0x100u, 0xc08c26e8u, 0xc08c26e8u, 0xc0284090u, 0x122u, 0u, 0x57f2u,
        0xc0044618u, 0x3b200000u, 0xe4adc180u, 4u, 0xea60u, 1u, 0x101u, 0xc08c271cu,
    };

    private static readonly uint[] Cleared24 = BuildCleared();

    private static uint[] BuildCleared()
    {
        var words = new uint[Enforcing24.Length];
        Array.Copy(Enforcing24, words, words.Length);
        words[1] = 0u;
        return words;
    }

    private sealed class Harness
    {
        public string Directory;
        public string ConfigPath;
        public string StatePath;
        public string ProbePath;
        public string RuntimeConfigPath;
        public string DotNetPath;
        public string BootIdPath;
        public readonly List<string[]> Calls = new List<string[]>();
        public Func<string[], UepGate.ProcessResult> Script;
        public string ProbeSha;
        public string RuntimeConfigSha;
    }

    private static Harness Setup(string configContent)
    {
        var harness = new Harness();
        harness.Directory = Path.Combine(Path.GetTempPath(),
            "tvroot-uep-host-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(harness.Directory);
        harness.ConfigPath = Path.Combine(harness.Directory, "uep-off.conf");
        harness.StatePath = Path.Combine(harness.Directory, "uep-state.conf");
        harness.ProbePath = Path.Combine(harness.Directory, "FdetProbe.dll");
        harness.RuntimeConfigPath = Path.Combine(harness.Directory, "FdetProbe.runtimeconfig.json");
        harness.DotNetPath = Path.Combine(harness.Directory, "dotnet");
        harness.BootIdPath = Path.Combine(harness.Directory, "boot_id");
        File.WriteAllText(harness.ProbePath, "fake FdetProbe payload bytes");
        File.WriteAllText(harness.RuntimeConfigPath, "{ }");
        File.WriteAllText(harness.DotNetPath, "#!fake dotnet");
        File.WriteAllText(harness.BootIdPath, "11112222-3333-4444-5555-666677778888");
        if (configContent != null) File.WriteAllText(harness.ConfigPath, configContent);
        harness.ProbeSha = Sha256File(harness.ProbePath);
        harness.RuntimeConfigSha = Sha256File(harness.RuntimeConfigPath);
        return harness;
    }

    private static void Cleanup(Harness h)
    {
        try { Directory.Delete(h.Directory, true); } catch { }
    }

    private static string Sha256File(string path)
    {
        var sha = System.Security.Cryptography.SHA256.Create();
        using (sha)
        using (var stream = File.OpenRead(path))
        {
            var digest = sha.ComputeHash(stream);
            var builder = new StringBuilder(digest.Length * 2);
            foreach (byte value in digest)
            {
                builder.Append(value.ToString("x2", CultureInfo.InvariantCulture));
            }

            return builder.ToString();
        }
    }

    private static string WordsBlock(string label, uint[] words)
    {
        var builder = new StringBuilder();
        for (int start = 0; start < words.Length; start += 8)
        {
            builder.Append(label).Append(" word=").Append(start.ToString(CultureInfo.InvariantCulture));
            for (int index = start; index < words.Length && index < start + 8; index++)
            {
                builder.Append(' ').Append(words[index].ToString("x8", CultureInfo.InvariantCulture));
            }

            builder.Append('\n');
        }

        return builder.ToString();
    }

    private static string ReadWordsOutput(uint[] words)
    {
        return "read_words physical=0x208c26c0 page=0x208c2000 offset=0x6c0 words=24\n"
            + WordsBlock("words", words);
    }

    private static string DumpOutput(uint[] before, uint[] after)
    {
        return WordsBlock("words_before", before) + WordsBlock("words_after", after);
    }

    private static int RunHost(Harness h, out string receipt)
    {
        var options = new UepGateHostOptions
        {
            ConfigPath = h.ConfigPath,
            StatePath = h.StatePath,
            ProbePath = h.ProbePath,
            RuntimeConfigPath = h.RuntimeConfigPath,
            DotNetPath = h.DotNetPath,
            BootIdPath = h.BootIdPath,
            ExpectedProbeSha256 = h.ProbeSha,
            ExpectedRuntimeConfigSha256 = h.RuntimeConfigSha,
            RunProbe = (string[] arguments) =>
            {
                h.Calls.Add(arguments);
                return h.Script(arguments);
            },
            Phase = "boot",
        };
        var writer = new StringWriter();
        int code = UepGateHost.Run(options, writer);
        receipt = writer.ToString();
        return code;
    }

    private static int Main()
    {
        try
        {
            // 1. Absent config: no probe call, exit 0, one receipt line.
            Harness absent = Setup(null);
            absent.Script = (string[] arguments) => throw new Exception("absent config must not probe");
            string receipt;
            Require(RunHost(absent, out receipt) == 0, "absent config must exit 0");
            Require(receipt.Contains("config absent (enforcing; no action)"), "absent receipt missing: " + receipt);
            Require(receipt.Contains("uep gate (boot) uid="), "uid receipt missing: " + receipt);
            Require(absent.Calls.Count == 0, "absent config invoked the probe");
            Require(!File.Exists(absent.StatePath), "absent config wrote budget state");
            Cleanup(absent);

            // 2. Invalid config: fail closed, no probe call.
            Harness invalid = Setup("nonsense\n");
            invalid.Script = (string[] arguments) => throw new Exception("invalid config must not probe");
            Require(RunHost(invalid, out receipt) == 0, "invalid config must exit 0");
            Require(receipt.Contains("unexpected config (fail closed)"), "invalid receipt missing: " + receipt);
            Require(invalid.Calls.Count == 0, "invalid config invoked the probe");
            Require(!File.Exists(invalid.StatePath), "invalid config wrote budget state");
            Cleanup(invalid);

            // 3. Read-only: exactly one read, zero stores, no budget file.
            Harness readOnly = Setup("read-only\n");
            readOnly.Script = (string[] arguments) =>
            {
                return new UepGate.ProcessResult
                {
                    ExitCode = 0, Completed = true, StdOut = ReadWordsOutput(Enforcing24), StdErr = ""
                };
            };
            Require(RunHost(readOnly, out receipt) == 0, "read-only must exit 0");
            Require(receipt.Contains("read-only: enforcing"), "read-only receipt missing: " + receipt);
            Require(readOnly.Calls.Count == 1, "read-only must probe once, got " + readOnly.Calls.Count);
            Require(readOnly.Calls[0].Length == 3 && readOnly.Calls[0][0] == "rw"
                && readOnly.Calls[0][1] == "0x208c26c0" && readOnly.Calls[0][2] == "24",
                "read-only probe arguments changed");
            Require(!File.Exists(readOnly.StatePath), "read-only wrote budget state");
            Cleanup(readOnly);

            // 4. Active: read then one guarded clear, receipted, budget saved.
            Harness active = Setup("active\n");
            active.Script = (string[] arguments) =>
            {
                if (arguments[0] == "rw")
                {
                    return new UepGate.ProcessResult
                    {
                        ExitCode = 0, Completed = true, StdOut = ReadWordsOutput(Enforcing24), StdErr = ""
                    };
                }

                return new UepGate.ProcessResult
                {
                    ExitCode = 0, Completed = true, StdOut = DumpOutput(Enforcing24, Cleared24), StdErr = ""
                };
            };
            Require(RunHost(active, out receipt) == 0, "active must exit 0");
            Require(receipt.Contains("cleared (boot)"), "active receipt missing: " + receipt);
            Require(active.Calls.Count == 2 && active.Calls[1][0] == "wwi"
                && active.Calls[1][1] == "0x208c26c0" && active.Calls[1][2] == "1"
                && active.Calls[1][3] == "00000001" && active.Calls[1][4] == "00000000",
                "active clear arguments changed");
            Require(File.Exists(active.StatePath), "active clear did not save the budget");
            Require(File.ReadAllText(active.StatePath).Contains("clear=1"), "budget receipt missing clear=1");
            Cleanup(active);

            // 5. Probe failure/crash: fail closed, exit 0 (module never fails a boot).
            Harness broken = Setup("active\n");
            broken.Script = (string[] arguments) => { throw new IOException("probe exploded"); };
            Require(RunHost(broken, out receipt) == 0, "probe failure must still exit 0");
            Require(receipt.Contains("fingerprint read failed (fail closed)"),
                "probe failure receipt missing: " + receipt);
            Require(!File.Exists(broken.StatePath), "failed read consumed budget");
            Cleanup(broken);

            Console.WriteLine("PASS: UEP gate host contract (absent/invalid/read-only/active/probe-failure)");
            return 0;
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL: " + e.Message);
            return 1;
        }
    }
}
