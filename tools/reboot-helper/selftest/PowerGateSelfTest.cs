using System;
using System.Collections.Generic;
using System.Text;

internal static class PowerGateSelfTest
{
    private static int tests;
    private static void Require(bool value, string message) { if (!value) throw new Exception(message); }
    private static void Refuse(Action call) { bool failed = false; try { call(); } catch { failed = true; } Require(failed, "expected refusal"); }

    public static int Main()
    {
        Dictionary<string, string> expected = new Dictionary<string, string> {
            {"boot", "test-boot"}, {"developer_ip", "192.0.2.1"}, {"pid_ns", "pid:[1]"}, {"user_ns", "user:[1]"}, {"host_mnt", "mnt:[1]"}
        };
        Dictionary<string, string> sample = new Dictionary<string, string> {
            {"agent", "1234"}, {"tid", "1234"}, {"NSpid", "1234"}, {"uid", "0 0 0 0"}, {"gid", "0 0 0 0"}, {"CapEff", "0000000000400001"},
            {"Seccomp", "0"}, {"NoNewPrivs", "0"}, {"label", "User"}, {"boot", "test-boot"},
            {"ip", "[system] db/sdk/develop/ip = String: 192.0.2.1"}, {"mode", "[system] db/sdk/develop/mode = Int32: 1"},
            {"init_comm", "systemd"}, {"init_ppid", "0"}, {"caller_pid", "pid:[1]"}, {"init_pid", "pid:[1]"},
            {"caller_user", "user:[1]"}, {"init_user", "user:[1]"}, {"caller_mnt", "mnt:[2]"}, {"init_mnt", "mnt:[1]"},
            {"caller_uid_map", "0 0 4294967295"}, {"caller_gid_map", "0 0 4294967295"},
            {"init_uid_map", "0 0 4294967295"}, {"init_gid_map", "0 0 4294967295"}
        };
        Func<Dictionary<string, string>, string> encode = data => {
            StringBuilder text = new StringBuilder();
            foreach (var pair in data) text.Append(pair.Key).Append('=').Append(pair.Value).Append('\n');
            return text.ToString();
        };
        LinuxRebootHelper.CheckSnapshot(encode(sample), expected, 1234);
        tests++;
        foreach (var change in new Dictionary<string, string> {
            {"uid", "901 901 901 901"}, {"gid", "901 901 901 901"}, {"CapEff", "0000000000000001"},
            {"Seccomp", "2"}, {"NoNewPrivs", "1"}, {"label", "System"}, {"boot", "wrong"},
            {"ip", "[system] db/sdk/develop/ip = String: 127.0.0.1"}, {"mode", "String: 1"},
            {"caller_pid", "pid:[2]"}, {"init_user", "user:[2]"}, {"caller_mnt", "mnt:[1]"},
            {"caller_uid_map", "0 1000 1"}, {"agent", "5678"}, {"init_ppid", "7"},
            {"NSpid", "1234 1"}, {"tid", "5678"}
        })
        {
            var invalid = new Dictionary<string, string>(sample);
            invalid[change.Key] = change.Value;
            Refuse(() => LinuxRebootHelper.CheckSnapshot(encode(invalid), expected, 1234));
            tests++;
        }
        foreach (bool power in new[] { false, true })
        {
            long now = 0; int sync = 0, reboot = 0, consumed = 0;
            RebootGate gate = new RebootGate(power, () => now);
            Func<NativeRebootResult> native = () => { reboot++; return new NativeRebootResult(-1, 1); };
            Refuse(() => gate.Commit(() => { }, () => consumed++, () => sync++, () => { }, native));
            gate.Ready(() => { }, () => { });
            NativeRebootResult result = gate.Commit(() => { }, () => consumed++, () => sync++, () => { }, native);
            Require(sync == (power ? 1 : 0) && reboot == (power ? 1 : 0) && consumed == 1, "native call count");
            Require(!power || result.ReturnValue == -1 && result.Errno == 1, "returned errno retained");
            Refuse(() => gate.Commit(() => { }, () => consumed++, () => sync++, () => { }, native));
            Refuse(() => gate.Ready(() => { }, () => { }));
            tests++;
        }
        foreach (string expiry in new[] { "before", "validate", "sync", "log" })
        {
            long now = 0; int calls = 0;
            RebootGate gate = new RebootGate(true, () => now);
            gate.Ready(() => { }, () => { });
            if (expiry == "before") now = 30000;
            Refuse(() => gate.Commit(
                () => { if (expiry == "validate") now = 30000; }, () => { },
                () => { if (expiry == "sync") now = 30000; },
                () => { if (expiry == "log") now = 30000; },
                () => { calls++; return new NativeRebootResult(0, 0); }));
            Require(calls == 0, "late reboot after expiry");
            tests++;
        }
        foreach (string fail in new[] { "context", "consume", "log" })
        {
            int calls = 0;
            RebootGate gate = new RebootGate(true, () => 0);
            gate.Ready(() => { }, () => { });
            Refuse(() => gate.Commit(
                () => { if (fail == "context") throw new Exception("context"); },
                () => { if (fail == "consume") throw new Exception("already consumed"); },
                () => { }, () => { if (fail == "log") throw new Exception("disk"); },
                () => { calls++; return new NativeRebootResult(0, 0); }));
            Require(calls == 0, "reboot after failed guard");
            tests++;
        }
        Console.WriteLine("{\"passed\":" + tests + ",\"real_native_calls\":0}");
        return 0;
    }
}
