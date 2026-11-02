using System;
using System.IO;

internal static class BridgePortSelfTest
{
    private static void Require(bool value, string message)
    {
        if (!value) throw new Exception(message);
    }

    private static void Reject<T>(Action action, string message) where T : Exception
    {
        try { action(); }
        catch (T) { return; }
        throw new Exception(message);
    }

    public static void Main()
    {
        string directory = Path.Combine(Path.GetTempPath(), "tvroot-bridge-port-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string config = Path.Combine(directory, "bridge-port.conf");
        var noArgs = Array.Empty<string>();
        try
        {
            Require(BridgeRelay.ReadPort(noArgs, config) == 26103, "missing file must use default");
            Require(BridgeRelay.ReadPort(noArgs, Path.Combine(directory, "missing", "port")) == 26103,
                "missing directory must use default");
            File.WriteAllText(config, "  29503\n");
            Require(BridgeRelay.ReadPort(noArgs, config) == 29503, "service startup must read configured port");
            Require(BridgeRelay.ReadPort(new[] { "26104" }, config) == 26104,
                "diagnostic port argument must override configuration");
            foreach (string value in new[] { "1024", "65535" })
            {
                File.WriteAllText(config, value);
                Require(BridgeRelay.ReadPort(noArgs, config) == int.Parse(value), "port boundary must be accepted");
            }
            foreach (string value in new[] { "", " ", "0", "1023", "65536", "-1", "2147483648", "port", "26103\n26104" })
            {
                File.WriteAllText(config, value);
                Reject<ArgumentException>(() => BridgeRelay.ReadPort(noArgs, config),
                    "invalid configuration must fail instead of using a different port");
                Reject<ArgumentException>(() => BridgeRelay.ReadPort(new[] { value }, config),
                    "invalid explicit port must fail");
            }
            Require(BridgeRelay.ReadPort(new[] { "26104" }, config) == 26104,
                "explicit port must ignore invalid configuration");
            Require(BridgeRelay.ReadPort(new[] { "26104" }, directory) == 26104,
                "explicit port must ignore unreadable configuration");
            Reject<UnauthorizedAccessException>(() => BridgeRelay.ReadPort(noArgs, directory),
                "configuration read errors must fail instead of using a different port");
            Require(BridgeRelay.Main(new[] { "65536" }) == 2, "startup must reject invalid ports before listening");
            Console.WriteLine("PASS: bridge port defaults, configuration, overrides, bounds and read failures");
        }
        finally
        {
            File.Delete(config);
            Directory.Delete(directory);
        }
    }
}
