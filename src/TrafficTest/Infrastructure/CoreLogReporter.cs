namespace TrafficTest;

internal static class CoreLogReporter
{
    public static async Task WaitForLogLineAsync(string logPath, string text, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (File.Exists(logPath) && ReadAllTextShared(logPath).Contains(text, StringComparison.Ordinal))
            {
                return;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new TimeoutException($"Timed out waiting for log line: {text}");
    }

    public static void PrintLogSummary(string logPath, bool includeRelevantLines)
    {
        if (!File.Exists(logPath))
        {
            Console.WriteLine("No core log found.");
            return;
        }

        var lines = ReadAllLinesShared(logPath);
        Console.WriteLine("core log summary:");
        PrintCounts(lines, ["APP TCP CONNECT", "APP UDP CONNECT"]);

        var errorPatterns = new[]
        {
            "DIRECT TCP connect failed",
            "DIRECT TCP send failed",
            "DIRECT TCP remote receive failed",
            "copy failed",
            "DIRECT UDP send failed",
            "UDP relay remote receive failed",
            "No direct target",
            "SendPacket"
        };
        PrintNonZeroCounts(lines, errorPatterns);

        var detailedPatterns = new[]
        {
            "TCP APP MATCH",
            "PASS RELAY TCP OUT",
            "PASS RELAY TCP IN",
            "DIRECT TCP CONNECT",
            "DIRECT TCP SEND",
            "DIRECT TCP RECV",
            "RESTORE TCP RECV",
            "UDP APP MATCH",
            "DIRECT UDP CAPTURE",
            "DIRECT UDP SEND",
            "DIRECT UDP RECV",
            "RESTORE UDP RECV"
        };
        if (includeRelevantLines || detailedPatterns.Any(pattern => Count(lines, pattern) > 0))
        {
            Console.WriteLine("detailed packet counters:");
            PrintCounts(lines, detailedPatterns);
        }

        if (includeRelevantLines)
        {
            Console.WriteLine("last relevant log lines:");
            foreach (var line in lines
                         .Where(IsRelevant)
                         .TakeLast(80))
            {
                Console.WriteLine(line);
            }
        }
    }

    private static string ReadAllTextShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static string[] ReadAllLinesShared(string path)
    {
        return ReadAllTextShared(path)
            .Split(["\r\n", "\n"], StringSplitOptions.None);
    }

    private static bool IsRelevant(string line)
    {
        return line.Contains("APP TCP CONNECT", StringComparison.Ordinal)
            || line.Contains("APP UDP CONNECT", StringComparison.Ordinal)
            || line.Contains("TCP APP MATCH", StringComparison.Ordinal)
            || line.Contains("RESTORE TCP", StringComparison.Ordinal)
            || line.Contains("PASS RELAY TCP", StringComparison.Ordinal)
            || line.Contains("DIRECT TCP", StringComparison.Ordinal)
            || line.Contains("UDP APP MATCH", StringComparison.Ordinal)
            || line.Contains("RESTORE UDP", StringComparison.Ordinal)
            || line.Contains("DIRECT UDP", StringComparison.Ordinal)
            || line.Contains("UDP relay", StringComparison.Ordinal)
            || line.Contains("failed", StringComparison.OrdinalIgnoreCase)
            || line.Contains("No direct target", StringComparison.Ordinal)
            || line.Contains("SendPacket", StringComparison.Ordinal);
    }

    private static void PrintCounts(IReadOnlyCollection<string> lines, IEnumerable<string> patterns)
    {
        foreach (var pattern in patterns)
        {
            Console.WriteLine($"  {pattern}: {Count(lines, pattern)}");
        }
    }

    private static void PrintNonZeroCounts(IReadOnlyCollection<string> lines, IEnumerable<string> patterns)
    {
        foreach (var pattern in patterns)
        {
            var count = Count(lines, pattern);
            if (count > 0)
            {
                Console.WriteLine($"  {pattern}: {count}");
            }
        }
    }

    private static int Count(IEnumerable<string> lines, string pattern)
    {
        return lines.Count(line => line.Contains(pattern, StringComparison.Ordinal));
    }
}
