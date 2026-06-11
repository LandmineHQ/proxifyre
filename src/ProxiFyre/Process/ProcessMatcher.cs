namespace ProxiFyre;

internal static class ProcessMatcher
{
    public static bool IsMatch(string pattern, ProcessInfo process)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        var normalizedPattern = pattern.Trim();
        var targetsPath = normalizedPattern.Contains('\\') || normalizedPattern.Contains('/');

        if (targetsPath)
        {
            return process.Path.Contains(normalizedPattern, StringComparison.OrdinalIgnoreCase);
        }

        return process.Name.Contains(normalizedPattern, StringComparison.OrdinalIgnoreCase);
    }
}

internal sealed record ProcessInfo(int ProcessId, string Name, string Path);
