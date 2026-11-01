using System;

internal static class CutoverSelfTest
{
    private static int passed;
    private static void Require(bool value, string message) { if (!value) throw new Exception(message); }
    private static void Refuse(Action call) { bool refused = false; try { call(); } catch { refused = true; } Require(refused, "expected refusal"); }
    public static int Main()
    {
        foreach (bool power in new[] { false, true })
        {
            int writes = 0, syncs = 0, calls = 0;
            var gate = new CutoverGate(power, () => 0);
            Refuse(() => gate.Switch(() => { }, () => { }, () => writes++, () => { }, () => { }));
            Refuse(() => gate.Commit(() => { }, () => { }, () => syncs++, () => { }, () => { calls++; return new NativeRebootResult(-1, 1); }));
            gate.Ready(() => { }, () => { });
            gate.Switch(() => { }, () => { }, () => writes++, () => { }, () => { });
            Refuse(() => gate.Switch(() => { }, () => { }, () => writes++, () => { }, () => { }));
            var result = gate.Commit(() => { }, () => { }, () => syncs++, () => { }, () => { calls++; return new NativeRebootResult(-1, 13); });
            Require(writes == (power ? 1 : 0) && syncs == (power ? 1 : 0) && calls == (power ? 1 : 0), "effect counts");
            Require(!power || result.ReturnValue == -1 && result.Errno == 13, "errno lost");
            Refuse(() => gate.Commit(() => { }, () => { }, () => syncs++, () => { }, () => { calls++; return result; }));
            Refuse(() => gate.Restore(() => false, () => writes++, () => { }));
            passed++;
        }
        foreach (string failure in new[] { "before", "consume", "write", "readback", "publish" })
        {
            int writes = 0, restores = 0;
            var gate = new CutoverGate(true, () => 0);
            gate.Ready(() => { }, () => { });
            Action<string> step = name => { if (name == failure) throw new Exception(name); };
            Refuse(() => gate.Switch(() => step("before"), () => step("consume"),
                () => { writes++; step("write"); }, () => step("readback"), () => step("publish")));
            gate.Restore(() => false, () => restores++, () => { });
            Require(restores == (writes == 1 ? 1 : 0), "pre-power restoration count");
            Refuse(() => gate.Commit(() => { }, () => { }, () => { }, () => { }, () => { throw new Exception("must not reboot"); }));
            if (writes == 1) Refuse(() => gate.Restore(() => false, () => restores++, () => { }));
            passed++;
        }
        foreach (string failure in new[] { "validate", "consume", "sync", "entry", "native" })
        {
            int restores = 0;
            var gate = new CutoverGate(true, () => 0);
            gate.Ready(() => { }, () => { });
            gate.Switch(() => { }, () => { }, () => { }, () => { }, () => { });
            Action<string> step = name => { if (name == failure) throw new Exception(name); };
            Refuse(() => gate.Commit(() => step("validate"), () => step("consume"), () => step("sync"), () => step("entry"), () => { step("native"); return new NativeRebootResult(-1, 1); }));
            Refuse(() => gate.Restore(() => false, () => restores++, () => { }));
            Require(restores == 0 && gate.PowerCommitted, "restoration after power acknowledgement");
            passed++;
        }
        foreach (string expiry in new[] { "before-write", "validate-before", "consume-ip", "after-write", "before-power", "validate-power", "sync", "entry" })
        {
            long now = 0;
            int calls = 0, writes = 0;
            var gate = new CutoverGate(true, () => now);
            gate.Ready(() => { }, () => { });
            if (expiry == "before-write") now = 30000;
            Action switching = () => gate.Switch(
                () => { if (expiry == "validate-before") now = 30000; },
                () => { if (expiry == "consume-ip") now = 30000; }, () => writes++,
                () => { if (expiry == "after-write") now = 30000; }, () => { });
            if (expiry == "before-write" || expiry == "validate-before" || expiry == "consume-ip" || expiry == "after-write") Refuse(switching);
            else
            {
                switching();
                if (expiry == "before-power") now = 30000;
                Refuse(() => gate.Commit(() => { if (expiry == "validate-power") now = 30000; }, () => { },
                    () => { if (expiry == "sync") now = 30000; }, () => { if (expiry == "entry") now = 30000; },
                    () => { calls++; return new NativeRebootResult(0, 0); }));
            }
            Require(calls == 0, "late reboot");
            Require(writes == (expiry == "before-write" || expiry == "validate-before" || expiry == "consume-ip" ? 0 : 1), "late IP write");
            passed++;
        }
        foreach (string state in new[] { "already-before", "unknown", "restore-write-fails", "restore-readback-fails" })
        {
            int writes = 0;
            var gate = new CutoverGate(true, () => 0);
            gate.Ready(() => { }, () => { });
            gate.Switch(() => { }, () => { }, () => { }, () => { }, () => { });
            Action restore = () => gate.Restore(() => { if (state == "unknown") throw new Exception("unknown boot/IP/context"); return state == "already-before"; },
                () => { writes++; if (state == "restore-write-fails") throw new Exception("setter"); },
                () => { if (state == "restore-readback-fails") throw new Exception("readback"); });
            if (state == "already-before") restore(); else Refuse(restore);
            Require(writes == (state == "already-before" || state == "unknown" ? 0 : 1), "unguarded restoration");
            Refuse(restore);
            Refuse(() => gate.Commit(() => { }, () => { }, () => { }, () => { }, () => { throw new Exception("reboot after restoration"); }));
            passed++;
        }
        string ack = "run_id=run\nconfig_sha256=code\nready_sha256=ready\n";
        LinuxCutoverHelper.CheckAcknowledgement(ack, "run", "code", "ready");
        foreach (string bad in new[] { ack.Replace("run_id=run", "run_id=other"), ack.Replace("code", "wrong"), ack.Replace("ready_sha256=ready", "ready_sha256=old"), ack + "run_id=run\n", ack + "extra=x\n", "invalid" })
        {
            Refuse(() => LinuxCutoverHelper.CheckAcknowledgement(bad, "run", "code", "ready"));
            passed++;
        }
        Console.WriteLine("{\"passed\":" + passed + ",\"real_setting_writes\":0,\"real_native_calls\":0}");
        return 0;
    }
}
