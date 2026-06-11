using System.IO;

namespace ProxiFyre;

internal static class ProcessMatcher
{
    public static bool IsMatch(string pattern, ProcessInfo process)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        var normalizedPattern = pattern.Trim().Trim('"');
        var targetsPath = normalizedPattern.Contains('\\') || normalizedPattern.Contains('/');

        if (targetsPath)
        {
            if (TryNormalizeDirectoryPattern(normalizedPattern, out var directoryPattern))
            {
                return IsProcessUnderDirectory(process.Path, directoryPattern);
            }

            if (TryNormalizeExecutablePath(normalizedPattern, out var executablePath))
            {
                return string.Equals(NormalizePath(process.Path), executablePath, StringComparison.OrdinalIgnoreCase);
            }

            return process.Path.Contains(normalizedPattern, StringComparison.OrdinalIgnoreCase);
        }

        return process.Name.Contains(normalizedPattern, StringComparison.OrdinalIgnoreCase);
    }

    public static bool TryNormalizeDirectoryPattern(string value, out string directoryPattern)
    {
        directoryPattern = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim().Trim('"');
        if (!Path.IsPathFullyQualified(trimmed))
        {
            return false;
        }

        var hasDirectorySuffix = EndsWithDirectorySeparator(trimmed);
        if (!hasDirectorySuffix && !Directory.Exists(trimmed))
        {
            return false;
        }

        try
        {
            var fullPath = Path.GetFullPath(trimmed);
            directoryPattern = EnsureTrailingDirectorySeparator(Path.TrimEndingDirectorySeparator(fullPath));
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static bool TryNormalizeExecutablePath(string value, out string executablePath)
    {
        executablePath = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim().Trim('"');
        if (!trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            || !Path.IsPathFullyQualified(trimmed))
        {
            return false;
        }

        executablePath = NormalizePath(trimmed);
        return executablePath.Length > 0;
    }

    private static bool IsProcessUnderDirectory(string processPath, string directoryPattern)
    {
        var normalizedProcessPath = NormalizePath(processPath);
        return normalizedProcessPath.Length > 0
            && normalizedProcessPath.StartsWith(directoryPattern, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        try
        {
            return Path.GetFullPath(value.Trim().Trim('"'));
        }
        catch
        {
            return value.Trim().Trim('"');
        }
    }

    private static string EnsureTrailingDirectorySeparator(string path)
    {
        return EndsWithDirectorySeparator(path)
            ? path
            : path + Path.DirectorySeparatorChar;
    }

    private static bool EndsWithDirectorySeparator(string path)
    {
        return path.EndsWith(Path.DirectorySeparatorChar)
            || path.EndsWith(Path.AltDirectorySeparatorChar);
    }
}

internal sealed record ProcessInfo(int ProcessId, string Name, string Path);
