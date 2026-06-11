using System.Diagnostics;

namespace TrafficTest;

internal static class ProcessIdentity
{
    public static string CreateTrafficTestAlias()
    {
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException("Could not resolve current TrafficTest executable path.");
        var aliasPath = Path.Combine(Path.GetDirectoryName(processPath)!, TrafficTestConstants.DefaultCoreProcessName);
        File.Copy(processPath, aliasPath, overwrite: true);
        return aliasPath;
    }

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
