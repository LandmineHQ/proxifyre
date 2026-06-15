using System.Diagnostics;

namespace TrafficTest;

internal static class ProcessIdentity
{
    public static string GetCurrentExecutableName()
    {
        var processPath = Environment.ProcessPath;
        if (!string.IsNullOrWhiteSpace(processPath))
        {
            return Path.GetFileName(processPath);
        }

        using var process = Process.GetCurrentProcess();
        return process.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? process.ProcessName
            : process.ProcessName + ".exe";
    }
}
