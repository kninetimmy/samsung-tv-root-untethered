using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

// Host-only fail-closed matrix for the QN90B UEP boot gate (UepGate.cs).
// A scripted runner stands in for FdetProbe.dll; every test pins the exact
// invocation arguments (target page, word offset, compare values, the full
// neighbour pin) or the store decisions, so a regression cannot widen the
// gate's write surface silently.
internal static class UepGateSelfTest
{
    private static void Require(bool value, string message)
    {
        if (!value) throw new Exception(message);
    }

    // The 24-word page neighbourhood recorded in the spent L2 packet
    // (cas-clear.json); the four-word enforcing fingerprint is the head.
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
        public readonly List<string> Logs = new List<string>();
        public Func<string[], UepGate.ProcessResult> Script;
        public string ProbeSha;
        public string RuntimeConfigSha;
    }

    private static Harness Setup(string name)
    {
        var harness = new Harness();
        harness.Directory = Path.Combine(Path.GetTempPath(),
            "tvroot-uep-gate-" + Guid.NewGuid().ToString("N"));
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
        harness.ProbeSha = Sha256File(harness.ProbePath);
        harness.RuntimeConfigSha = Sha256File(harness.RuntimeConfigPath);
        return harness;
    }

    private static UepGate NewGate(Harness h)
    {
        return new UepGate(h.ConfigPath, h.StatePath, h.ProbePath, h.RuntimeConfigPath,
            h.DotNetPath, h.BootIdPath, h.ProbeSha, h.RuntimeConfigSha,
            (string[] arguments) =>
            {
                h.Calls.Add(arguments);
                return h.Script != null
                    ? h.Script(arguments)
                    : new UepGate.ProcessResult { ExitCode = 1, Completed = true, StdOut = "", StdErr = "scripted refusal" };
            },
            (string text) => h.Logs.Add(text));
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

    private static bool IsMode(string[] arguments, string mode)
    {
        return arguments.Length >= 1 && arguments[0] == mode;
    }

    private static int CountMode(Harness h, string mode)
    {
        int count = 0;
        foreach (string[] arguments in h.Calls)
        {
            if (IsMode(arguments, mode)) count++;
        }

        return count;
    }

    public static void Main()
    {
        // 1. No config: the gate must never touch the Targal state.
        Harness absent = Setup("absent");
        try
        {
            string outcome = NewGate(absent).Run("boot");
            Require(absent.Calls.Count == 0, "absent config must never run the probe");
            Require(!File.Exists(absent.StatePath), "absent config must not create state");
            Require(outcome.Contains("config absent"), "absent config outcome should say so");
        }
        finally { Cleanup(absent); }

        // 2. Config with unexpected content fails closed.
        Harness invalid = Setup("invalid");
        try
        {
            File.WriteAllText(invalid.ConfigPath, "banana");
            Require(NewGate(invalid).Run("boot").Contains("unexpected config"),
                "invalid config must fail closed");
            Require(invalid.Calls.Count == 0, "invalid config must never run the probe");
            File.WriteAllText(invalid.ConfigPath, "");
            Require(NewGate(invalid).Run("boot").Contains("unexpected config"),
                "empty config must fail closed");
        }
        finally { Cleanup(invalid); }

        // 3. Hash pinning: wrong probe bytes must stop everything.
        Harness wrongSha = Setup("wrong-sha");
        try
        {
            File.WriteAllText(wrongSha.ConfigPath, "active");
            var mismatched = new UepGate(wrongSha.ConfigPath, wrongSha.StatePath, wrongSha.ProbePath,
                wrongSha.RuntimeConfigPath, wrongSha.DotNetPath, wrongSha.BootIdPath,
                "0".PadRight(64, '0'), wrongSha.RuntimeConfigSha,
                (string[] arguments) => throw new Exception("must not be invoked"),
                (string text) => wrongSha.Logs.Add(text));
            Require(mismatched.Run("boot").Contains("fail closed"), "hash mismatch must fail closed");
            Require(wrongSha.Calls.Count == 0, "hash mismatch must never run the probe");
        }
        finally { Cleanup(wrongSha); }

        // 4. dotnet missing: refuse before any probe run.
        Harness noDotnet = Setup("no-dotnet");
        try
        {
            File.WriteAllText(noDotnet.ConfigPath, "active");
            File.Delete(noDotnet.DotNetPath);
            Require(NewGate(noDotnet).Run("boot").Contains("fail closed"),
                "missing dotnet must fail closed");
            Require(noDotnet.Calls.Count == 0, "missing dotnet must never run the probe");
        }
        finally { Cleanup(noDotnet); }

        // 5. Config present but probe files missing.
        Harness noProbe = Setup("no-probe");
        try
        {
            File.WriteAllText(noProbe.ConfigPath, "active");
            File.Delete(noProbe.ProbePath);
            Require(NewGate(noProbe).Run("boot").Contains("fail closed"),
                "missing probe files must fail closed");
            Require(noProbe.Calls.Count == 0, "missing probe must never run");
        }
        finally { Cleanup(noProbe); }

        // 6. Corrupt budget state disables stores.
        Harness corruptState = Setup("corrupt-state");
        try
        {
            File.WriteAllText(corruptState.ConfigPath, "active");
            File.WriteAllText(corruptState.StatePath, "nonsense gibberish");
            Require(NewGate(corruptState).Run("boot").Contains("corrupt budget state"),
                "corrupt state must fail closed");
            Require(corruptState.Calls.Count == 0, "corrupt state must never run the probe");
        }
        finally { Cleanup(corruptState); }

        // 7. Unreadable boot id disables stores.
        Harness noBootId = Setup("no-boot-id");
        try
        {
            File.WriteAllText(noBootId.ConfigPath, "active");
            File.Delete(noBootId.BootIdPath);
            Require(NewGate(noBootId).Run("boot").Contains("fail closed"),
                "missing boot id must fail closed");
            Require(noBootId.Calls.Count == 0, "missing boot id must never run the probe");
        }
        finally { Cleanup(noBootId); }

        // 8. Boot id with unexpected characters disables stores.
        Harness badBootId = Setup("bad-boot-id");
        try
        {
            File.WriteAllText(badBootId.ConfigPath, "active");
            File.WriteAllText(badBootId.BootIdPath, "not a boot id");
            Require(NewGate(badBootId).Run("boot").Contains("fail closed"),
                "garbled boot id must fail closed");
            Require(badBootId.Calls.Count == 0, "garbled boot id must never run the probe");
        }
        finally { Cleanup(badBootId); }

        // 9. Read-only mode: one read, zero stores, honest classification.
        foreach (uint[] words in new[] { Enforcing24, Cleared24 })
        {
            Harness read = Setup("read-only-" + words[1]);
            try
            {
                File.WriteAllText(read.ConfigPath, "read-only");
                read.Script = (string[] arguments) =>
                {
                    return new UepGate.ProcessResult { ExitCode = 0, Completed = true, StdOut = ReadWordsOutput(words), StdErr = "" };
                };
                string outcome = NewGate(read).Run("boot");
                Require(outcome.Contains("read-only:"), "read-only outcome must be honest: " + outcome);
                Require(outcome.Contains(words[1] == 1u ? "enforcing" : "cleared"),
                    "read-only must classify the observed state: " + outcome);
                Require(read.Calls.Count == 1 && IsMode(read.Calls[0], "rw"),
                    "read-only must issue exactly one read");
                Require(!File.Exists(read.StatePath) || File.ReadAllText(read.StatePath).Contains("clear=0 restore=0"),
                    "read-only must not consume budget");
            }
            finally { Cleanup(read); }
        }

        // 10. Read-only with a failing read must be honest too.
        Harness readFail = Setup("read-fail");
        try
        {
            File.WriteAllText(readFail.ConfigPath, "read-only");
            readFail.Script = (string[] arguments) => new UepGate.ProcessResult
            {
                ExitCode = 1, Completed = true, StdOut = "", StdErr = "word mmap read failed errno=5"
            };
            Require(NewGate(readFail).Run("boot").Contains("fingerprint read failed"),
                "read-only must report read failure verbatim");
        }
        finally { Cleanup(readFail); }

        // 11. Active + already cleared: idle, zero stores, no budget consumed.
        Harness idle = Setup("idle");
        try
        {
            File.WriteAllText(idle.ConfigPath, "active");
            File.WriteAllText(idle.StatePath, "boot=11112222-3333-4444-5555-666677778888 clear=0 restore=0");
            idle.Script = (string[] arguments) => new UepGate.ProcessResult
            {
                ExitCode = 0, Completed = true, StdOut = ReadWordsOutput(Cleared24), StdErr = ""
            };
            Require(NewGate(idle).Run("boot").Contains("already cleared"),
                "cleared state must idle");
            Require(idle.Calls.Count == 1 && IsMode(idle.Calls[0], "rw"), "idle must only read");
            Require(File.ReadAllText(idle.StatePath).Trim() == "boot=11112222-3333-4444-5555-666677778888 clear=0 restore=0",
                "idle must not touch the budget");
        }
        finally { Cleanup(idle); }

        // 12. Active + unexpected fingerprint: fail closed, zero stores.
        Harness unexpected = Setup("unexpected");
        try
        {
            File.WriteAllText(unexpected.ConfigPath, "active");
            unexpected.Script = (string[] arguments) => new UepGate.ProcessResult
            {
                ExitCode = 0, Completed = true, StdOut = ReadWordsOutput(new uint[]
                {
                    0xdeadbeefu, 1u, 0u, 0x4e2u, 0xau, 0u, 0u, 0u,
                    0u, 0x100u, 0xc08c26e8u, 0xc08c26e8u, 0xc0284090u, 0x122u, 0u, 0x57f2u,
                    0xc0044618u, 0x3b200000u, 0xe4adc180u, 4u, 0xea60u, 1u, 0x101u, 0xc08c271cu,
                }), StdErr = ""
            };
            Require(NewGate(unexpected).Run("boot").Contains("unexpected fingerprint"),
                "unexpected fingerprint must fail closed");
            Require(unexpected.Calls.Count == 1, "unexpected fingerprint must not store");
        }
        finally { Cleanup(unexpected); }

        // 13. Happy path: exact wwi arguments, exact neighbour pin, budget saved.
        Harness success = Setup("success");
        try
        {
            File.WriteAllText(success.ConfigPath, "active");
            int wwiSO = 0;
            success.Script = (string[] arguments) =>
            {
                if (IsMode(arguments, "rw"))
                {
                    return new UepGate.ProcessResult { ExitCode = 0, Completed = true, StdOut = ReadWordsOutput(Enforcing24), StdErr = "" };
                }

                if (IsMode(arguments, "wwi"))
                {
                    wwiSO++;
                    return new UepGate.ProcessResult { ExitCode = 0, Completed = true, StdOut = DumpOutput(Enforcing24, Cleared24), StdErr = "" };
                }

                throw new Exception("unexpected mode");
            };
            string outcome = NewGate(success).Run("boot");
            Require(outcome == "cleared (boot)", "success run summary: " + outcome);
            Require(success.Calls.Count == 2, "success run must read once, clear once");
            string[] wwi = success.Calls[1];
            Require(wwi.Length == 6, "wwi must pass six arguments");
            Require(wwi[1] == "0x208c26c0", "wwi must target the validated page");
            Require(wwi[2] == "1", "wwi offset must be the exact page word");
            Require(wwi[3] == "00000001", "wwi compare value must be the enforcing word");
            Require(wwi[4] == "00000000", "wwi replacement must be the cleared word");
            Require(wwi[5] == ExpectedPin(Enforcing24),
                "wwi must pin the full observed neighbourhood except the target word");
            Require(File.ReadAllText(success.StatePath) == "boot=11112222-3333-4444-5555-666677778888 clear=1 restore=0\n",
                "success must record one clear");
            Require(wwiSO == 1, "exactly one store");
        }
        finally { Cleanup(success); }

        // 14. Clear refused with no state change: no restore, budget saved.
        Harness refused = Setup("refused-enforcing");
        try
        {
            File.WriteAllText(refused.ConfigPath, "active");
            int reads = 0;
            refused.Script = (string[] arguments) =>
            {
                if (IsMode(arguments, "rw"))
                {
                    reads++;
                    return new UepGate.ProcessResult
                    {
                        ExitCode = 0, Completed = true, StdOut = ReadWordsOutput(Enforcing24), StdErr = ""
                    };
                }

                return new UepGate.ProcessResult
                {
                    ExitCode = 1, Completed = true,
                    StdErr = "refusing write word=1 expected=0x00000001 actual=0x00000002"
                };
            };
            Require(NewGate(refused).Run("boot").Contains("clear did not take"),
                "refused clear with enforcing state must not restore");
            Require(CountMode(refused, "wwi") == 1, "refused clear must not trigger a restore");
            Require(reads == 2, "refused clear must re-check state once");
        }
        finally { Cleanup(refused); }

        // 15. Clear timeout with cleared result: one guarded restore.
        Harness timedOutRestored = Setup("timeout-restored");
        try
        {
            File.WriteAllText(timedOutRestored.ConfigPath, "active");
            int wwiSeen = 0;
            timedOutRestored.Script = (string[] arguments) =>
            {
                if (IsMode(arguments, "rw"))
                {
                    int count = 0;
                    foreach (string[] past in timedOutRestored.Calls)
                    {
                        if (IsMode(past, "rw")) count++;
                    }

                    return new UepGate.ProcessResult
                    {
                        ExitCode = 0, Completed = true,
                        StdOut = ReadWordsOutput(count <= 1 ? Enforcing24 : Cleared24), StdErr = ""
                    };
                }

                wwiSeen++;
                if (wwiSeen == 1)
                {
                    return new UepGate.ProcessResult { ExitCode = -1, Completed = false, StdOut = "", StdErr = "timed out" };
                }

                return new UepGate.ProcessResult { ExitCode = 0, Completed = true, StdOut = DumpOutput(Cleared24, Enforcing24), StdErr = "" };
            };
            Require(NewGate(timedOutRestored).Run("boot").Contains("restored to enforcing"),
                "timeout with observed cleared state must attempt the guarded restore");
            Require(CountMode(timedOutRestored, "wwi") == 2, "restore must be a single second store");
            Require(File.ReadAllText(timedOutRestored.StatePath) == "boot=11112222-3333-4444-5555-666677778888 clear=1 restore=1\n",
                "restore must consume its budget");
        }
        finally { Cleanup(timedOutRestored); }

        // 16. Restore budget exhausted: cleared-but-unverified never re-stores.
        Harness restoreGone = Setup("restore-budget");
        try
        {
            File.WriteAllText(restoreGone.ConfigPath, "active");
            File.WriteAllText(restoreGone.StatePath, "boot=11112222-3333-4444-5555-666677778888 clear=0 restore=1");
            int reads = 0;
            restoreGone.Script = (string[] arguments) =>
            {
                if (IsMode(arguments, "rw"))
                {
                    reads++;
                    return new UepGate.ProcessResult
                    {
                        ExitCode = 0,
                        Completed = true,
                        StdOut = ReadWordsOutput(reads <= 1 ? Enforcing24 : Cleared24),
                        StdErr = "",
                    };
                }

                return new UepGate.ProcessResult { ExitCode = -1, Completed = false, StdOut = "", StdErr = "timed out" };
            };
            Require(NewGate(restoreGone).Run("boot").Contains("restore budget exhausted"),
                "restore budget must be respected");
            Require(CountMode(restoreGone, "wwi") == 1, "no restore beyond the budget");
        }
        finally { Cleanup(restoreGone); }

        // 17. Clear budget exhausted: no store at all.
        Harness clearGone = Setup("clear-budget");
        try
        {
            File.WriteAllText(clearGone.ConfigPath, "active");
            File.WriteAllText(clearGone.StatePath, "boot=11112222-3333-4444-5555-666677778888 clear=2 restore=0");
            clearGone.Script = (string[] arguments) =>
                new UepGate.ProcessResult { ExitCode = 0, Completed = true, StdOut = ReadWordsOutput(Enforcing24), StdErr = "" };
            Require(NewGate(clearGone).Run("boot").Contains("clear budget exhausted"),
                "clear budget must be respected");
            Require(CountMode(clearGone, "wwi") == 0, "budget exhaustion must not store");
        }
        finally { Cleanup(clearGone); }

        // 18. Boot id rotation resets the budget.
        Harness rotated = Setup("boot-rotate");
        try
        {
            File.WriteAllText(rotated.ConfigPath, "active");
            File.WriteAllText(rotated.StatePath, "boot=aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000 clear=2 restore=1");
            rotated.Script = (string[] arguments) =>
            {
                if (IsMode(arguments, "rw"))
                {
                    return new UepGate.ProcessResult { ExitCode = 0, Completed = true, StdOut = ReadWordsOutput(Enforcing24), StdErr = "" };
                }

                return new UepGate.ProcessResult { ExitCode = 0, Completed = true, StdOut = DumpOutput(Enforcing24, Cleared24), StdErr = "" };
            };
            Require(NewGate(rotated).Run("boot") == "cleared (boot)", "new boot must allow one clear");
            Require(File.ReadAllText(rotated.StatePath)
                == "boot=11112222-3333-4444-5555-666677778888 clear=1 restore=0\n",
                "boot rotation must reset the budget under the new boot id");
        }
        finally { Cleanup(rotated); }

        // 19. Receipt with two changed words: anomaly path, restore still bounded.
        Harness twoChanges = Setup("two-changes");
        try
        {
            File.WriteAllText(twoChanges.ConfigPath, "active");
            var polluted = (uint[])Cleared24.Clone();
            polluted[5] = 0x1234u;
            int wwiCalls = 0;
            twoChanges.Script = (string[] arguments) =>
            {
                if (IsMode(arguments, "rw"))
                {
                    int count = 0;
                    foreach (string[] past in twoChanges.Calls)
                    {
                        if (IsMode(past, "rw")) count++;
                    }

                    return new UepGate.ProcessResult
                    {
                        ExitCode = 0, Completed = true,
                        StdOut = ReadWordsOutput(count <= 1 ? Enforcing24 : Cleared24), StdErr = ""
                    };
                }

                wwiCalls++;
                return wwiCalls == 1
                    ? new UepGate.ProcessResult
                    {
                        ExitCode = 0, Completed = true,
                        StdOut = WordsBlock("words_before", Enforcing24) + WordsBlock("words_after", polluted),
                        StdErr = "",
                    }
                    : new UepGate.ProcessResult
                    {
                        ExitCode = 0, Completed = true,
                        StdOut = DumpOutput(Cleared24, Enforcing24), StdErr = "",
                    };
            };
            Require(NewGate(twoChanges).Run("boot").Contains("restored to enforcing"),
                "ambiguous receipt with observed cleared state must restore once");
        }
        finally { Cleanup(twoChanges); }

        // 20. Restore that does not confirm must be reported unverified.
        Harness restoreUnconfirmed = Setup("restore-unconfirmed");
        try
        {
            File.WriteAllText(restoreUnconfirmed.ConfigPath, "active");
            int reads = 0;
            int wwiSeen = 0;
            restoreUnconfirmed.Script = (string[] arguments) =>
            {
                if (IsMode(arguments, "rw"))
                {
                    reads++;
                    return new UepGate.ProcessResult
                    {
                        ExitCode = 0,
                        Completed = true,
                        StdOut = ReadWordsOutput(reads <= 1 ? Enforcing24 : Cleared24),
                        StdErr = "",
                    };
                }

                // First wwi (clear): timeout. Second wwi (restore): refused.
                wwiSeen++;
                return wwiSeen == 1
                    ? new UepGate.ProcessResult { ExitCode = -1, Completed = false, StdOut = "", StdErr = "timed out" }
                    : new UepGate.ProcessResult { ExitCode = 1, Completed = true, StdOut = "", StdErr = "refusing write" };
            };
            Require(NewGate(restoreUnconfirmed).Run("boot").Contains("restore unconfirmed"),
                "unconfirmed restore must say so");
        }
        finally { Cleanup(restoreUnconfirmed); }

        // 21. Refusals consume the clear budget but stay bounded across relaunches.
        Harness refusal = Setup("refusals");
        try
        {
            File.WriteAllText(refusal.ConfigPath, "active");
            refusal.Script = (string[] arguments) =>
            {
                if (IsMode(arguments, "rw"))
                {
                    return new UepGate.ProcessResult { ExitCode = 0, Completed = true, StdOut = ReadWordsOutput(Enforcing24), StdErr = "" };
                }

                return new UepGate.ProcessResult
                {
                    ExitCode = 1, Completed = true,
                    StdErr = "refusing write word=1 expected=0x00000001 actual=0x00000002"
                };
            };
            string first = NewGate(refusal).Run("boot");
            Require(first.Contains("clear did not take"), "refused clear reported: " + first);
            string second = NewGate(refusal).Run("reopen");
            Require(second.Contains("clear did not take"), "second attempt reported: " + second);
            Require(CountMode(refusal, "wwi") == 2, "refusals consume budget but stay bounded (2 of 2)");
            string third = NewGate(refusal).Run("reopen");
            Require(third.Contains("clear budget exhausted"), "third attempt must refuse: " + third);
            Require(CountMode(refusal, "wwi") == 2, "budget must hold at two");
        }
        finally { Cleanup(refusal); }

        // 22. Every invocation targets only the validated page.
        Harness pageOnly = Setup("page-only");
        try
        {
            File.WriteAllText(pageOnly.ConfigPath, "active");
            pageOnly.Script = (string[] arguments) =>
            {
                if (IsMode(arguments, "rw"))
                {
                    return new UepGate.ProcessResult { ExitCode = 0, Completed = true, StdOut = ReadWordsOutput(Enforcing24), StdErr = "" };
                }

                return new UepGate.ProcessResult { ExitCode = 0, Completed = true, StdOut = DumpOutput(Enforcing24, Cleared24), StdErr = "" };
            };
            NewGate(pageOnly).Run("boot");
            Require(pageOnly.Calls.Count == 2, "page-only sanity");
            foreach (string[] arguments in pageOnly.Calls)
            {
                Require(arguments[1] == "0x208c26c0", "every probe call must use the validated page: " + arguments[1]);
            }
        }
        finally { Cleanup(pageOnly); }

        // 23. The production constants must match the spent packet's receipts.
        Require(UepGate.ProductionProbeSha256 == "2cfec6d19ab3ddcc7eb5ec4fe0cb511bf45864994cf990daf2e1ea722b88a8bb",
            "probe sha pin must match the live-validated payload");
        Require(UepGate.ProductionRuntimeConfigSha256 == "2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b",
            "runtimeconfig sha pin must match the live-validated payload");
        Require(UepGate.ProductionProbePath == "/opt/usr/share/selfroot/fdetprobe/FdetProbe.dll",
            "probe path constant must stay where deployment expects it");
        Require(UepGate.ProductionConfigPath == "/opt/usr/share/selfroot/uep-off.conf",
            "config path constant must stay where deployment expects it");

        Console.WriteLine("PASS: UEP gate config/budget/fingerprint/store/anomaly fail-closed matrix");
    }

    private static string ExpectedPin(uint[] words)
    {
        var builder = new StringBuilder();
        for (int offset = 0; offset < words.Length; offset++)
        {
            if (offset == 1) continue;
            if (builder.Length > 0) builder.Append(",");
            builder.Append(offset.ToString(CultureInfo.InvariantCulture)).Append(":")
                .Append(words[offset].ToString("x8", CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }
}
