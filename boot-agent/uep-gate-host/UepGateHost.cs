using System;
using System.IO;

// v5.19: production host for the L4 UEP gate, executed from the ROOT boot
// module context. The v5.18 manager ran UepGate inside the app process (uid
// 901, User::Pkg::ghservice::RO) where /usr/bin/dotnet is not visible, so the
// payload check failed closed on every boot with a config present. This host
// keeps the gate logic (UepGate.cs) unchanged and only relocates where it
// executes: the module runner already runs every /opt boot module as uid 0
// after the root proof is published.
//
// Fail-closed contract, unchanged from UepGate.cs: an absent config touches
// nothing, unknown content fails closed, read-only performs one fingerprint
// read and zero stores, and only "active" may clear. This host adds no store
// path of its own; it prints the gate's one-line receipt and exits 0 for every
// fail-closed outcome so a boot module never looks like a boot failure.
internal sealed class UepGateHostOptions
{
    public string ConfigPath = UepGate.ProductionConfigPath;
    public string StatePath = UepGate.ProductionStatePath;
    public string ProbePath = UepGate.ProductionProbePath;
    public string RuntimeConfigPath = UepGate.ProductionRuntimeConfigPath;
    public string DotNetPath = UepGate.ProductionDotNetPath;
    public string BootIdPath = UepGate.ProductionBootIdPath;
    public string ExpectedProbeSha256 = UepGate.ProductionProbeSha256;
    public string ExpectedRuntimeConfigSha256 = UepGate.ProductionRuntimeConfigSha256;
    public UepGate.ProbeRunner RunProbe = UepGate.RunProductionProbe;
    public string Phase = "boot";
}

internal static class UepGateHost
{
    public static int Run(UepGateHostOptions options, TextWriter output)
    {
        if (options == null) throw new ArgumentNullException("options");
        if (output == null) throw new ArgumentNullException("output");

        try
        {
            var gate = new UepGate(
                options.ConfigPath,
                options.StatePath,
                options.ProbePath,
                options.RuntimeConfigPath,
                options.DotNetPath,
                options.BootIdPath,
                options.ExpectedProbeSha256,
                options.ExpectedRuntimeConfigSha256,
                options.RunProbe,
                (string text) => output.WriteLine("uep gate: " + text));
            string summary = gate.Run(options.Phase);
            output.WriteLine("uep gate (" + options.Phase + ") uid=" + ReadUid()
                + ": " + summary);
            output.Flush();
            return 0;
        }
        catch (Exception e)
        {
            try
            {
                output.WriteLine("uep gate (" + options.Phase + ") EXCEPTION "
                    + e.GetType().Name + ": " + Compress(e.Message));
                output.Flush();
            }
            catch { }
            return 1;
        }
    }

    // The module runner guarantees uid 0; recording it makes every gate line
    // self-evidencing for the deployment packet's receipts.
    private static string ReadUid()
    {
        try
        {
            foreach (string line in File.ReadAllLines("/proc/self/status"))
            {
                if (!line.StartsWith("Uid:", StringComparison.Ordinal)) continue;
                string[] columns = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                return columns.Length >= 2 ? columns[1] : "unknown";
            }
        }
        catch (Exception) { }
        return "unknown";
    }

    private static string Compress(string message)
    {
        if (message == null) return "";
        string flat = message.Replace("\r", " ").Replace("\n", " ");
        return flat.Length <= 120 ? flat : flat.Substring(0, 120);
    }
}
