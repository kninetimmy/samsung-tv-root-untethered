using System;

// v5.19 root-context UEP gate entry point. One optional argument: a phase
// label recorded in the receipt line ("boot" by default, "manual" for a
// packet-run diagnostic read). No other switches: the gate's behaviour is
// driven only by /opt/usr/share/selfroot/uep-off.conf.
internal static class Program
{
    private const int MaximumPhaseLength = 16;

    private static int Main(string[] arguments)
    {
        var options = new UepGateHostOptions();
        if (arguments.Length > 1)
        {
            Console.Error.WriteLine("usage: UepGateHost [phase]");
            return 2;
        }

        if (arguments.Length == 1)
        {
            if (!IsPhase(arguments[0]))
            {
                Console.Error.WriteLine("invalid phase label (1-" + MaximumPhaseLength
                    + " lowercase letters or '-')");
                return 2;
            }

            options.Phase = arguments[0];
        }

        return UepGateHost.Run(options, Console.Out);
    }

    private static bool IsPhase(string value)
    {
        if (value == null || value.Length == 0 || value.Length > MaximumPhaseLength) return false;
        foreach (char character in value)
        {
            bool allowed = (character >= 'a' && character <= 'z') || character == '-';
            if (!allowed) return false;
        }

        return true;
    }
}
