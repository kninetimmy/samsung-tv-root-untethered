using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;

// Direct Process.Start reports execve errno separately from a child's exit.
// No shell, native fallback, retries, gate writes or reboot API.
public static class DenialRunner
{
    public static int Attempt(Func<Process> start, TextWriter output)
    {
        Process child;
        try { child = start(); }
        catch (Win32Exception error)
        {
            output.WriteLine(JsonSerializer.Serialize(new {
                exec_started = false, errno = error.NativeErrorCode,
                native_exit = (int?)null, timed_out = false, stdout = "", stderr = ""
            }));
            return 77; // refusal, never a successful native child exit
        }
        if (child == null) throw new InvalidOperationException("Process.Start returned null");
        using (child)
        {
            var stdout = child.StandardOutput.ReadToEndAsync();
            var stderr = child.StandardError.ReadToEndAsync();
            bool completed = child.WaitForExit(5000);
            if (!completed)
            {
                child.Kill(); // this Process handle, never a shell/PID lookup
                if (!child.WaitForExit(1000)) throw new TimeoutException("owned child did not exit after kill");
            }
            if (!System.Threading.Tasks.Task.WaitAll(new System.Threading.Tasks.Task[] { stdout, stderr }, 1000))
                throw new TimeoutException("owned child output did not close");
            output.WriteLine(JsonSerializer.Serialize(new {
                exec_started = true, errno = (int?)null, native_exit = (int?)child.ExitCode,
                timed_out = !completed, stdout = stdout.Result, stderr = stderr.Result
            }));
            return 78; // ANY started child is failure for this denial control
        }
    }

    public static int Main(string[] args)
    {
        if (args.Length != 1 || !System.Text.RegularExpressions.Regex.IsMatch(args[0],
            @"^/home/owner/share/tmp/sdk_tools/denial-[0-9a-f]{16}/uep-probe\.elf$"))
            throw new ArgumentException("one exact denial staging path required");
        return Attempt(() => Process.Start(new ProcessStartInfo {
            FileName = args[0], UseShellExecute = false,
            RedirectStandardOutput = true, RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(args[0])
        }), Console.Out);
    }
}
