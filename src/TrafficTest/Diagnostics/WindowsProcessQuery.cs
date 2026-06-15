using System.Diagnostics;

namespace TrafficTest;

internal static class WindowsProcessQuery
{
    public static IReadOnlyList<WindowsProcessSnapshot> GetByName(string processName)
    {
        var normalized = NormalizeProcessName(processName);
        return Process.GetProcesses()
            .Where(process => NormalizeProcessName(process.ProcessName).Equals(normalized, StringComparison.OrdinalIgnoreCase))
            .Select(CreateSnapshot)
            .OrderBy(process => process.ProcessId)
            .ToArray();
    }

    public static IReadOnlyList<WindowsProcessSnapshot> GetByIds(IEnumerable<int> processIds)
    {
        var ids = processIds.ToHashSet();
        return Process.GetProcesses()
            .Where(process => ids.Contains(process.Id))
            .Select(CreateSnapshot)
            .OrderBy(process => process.ProcessId)
            .ToArray();
    }

    public static string? TryGetProcessPath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static WindowsProcessSnapshot CreateSnapshot(Process process)
    {
        return new WindowsProcessSnapshot(
            process.Id,
            NormalizeProcessName(process.ProcessName),
            TryGetProcessPath(process));
    }

    private static string NormalizeProcessName(string processName)
    {
        return processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? processName
            : processName + ".exe";
    }
}

internal sealed record WindowsProcessSnapshot(
    int ProcessId,
    string ProcessName,
    string? ExecutablePath);
