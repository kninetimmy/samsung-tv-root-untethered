using System;

internal static class AutoCloseSelfTest
{
    private static void Require(bool value, string message)
    {
        if (!value) throw new Exception(message);
    }

    public static void Main()
    {
        var close = new SuccessAutoClose();
        Require(!close.ShouldClose(0, false), "startup must stay visible");
        Require(!close.ShouldClose(360000, false), "failure or missing bridge must stay visible");
        Require(!close.ShouldClose(400000, true), "readiness starts a fresh countdown");
        Require(!close.ShouldClose(409999, true), "must wait the full ten seconds");
        Require(close.ShouldClose(410000, true), "must close at ten seconds");

        var resumed = new SuccessAutoClose();
        Require(!resumed.ShouldClose(1000, true), "first ready tick must not close");
        Require(!resumed.ShouldClose(6000, true), "repeated ticks must not restart countdown");
        Require(resumed.ShouldClose(61000, true), "pause/resume must not restart countdown");

        var interrupted = new SuccessAutoClose();
        Require(!interrupted.ShouldClose(0, true), "initial readiness starts countdown");
        Require(!interrupted.ShouldClose(10000, false), "lost readiness must prevent exit");
        Require(!interrupted.ShouldClose(20000, true), "restored readiness starts fresh countdown");
        Require(interrupted.ShouldClose(30000, true), "restored readiness closes after ten seconds");
        Console.WriteLine("PASS: 12 auto-close timing checks (no TV or sleep required)");
    }
}
