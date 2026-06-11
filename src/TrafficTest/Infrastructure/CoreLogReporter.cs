namespace TrafficTest;

internal static class CoreLogReporter
{
    public static void PrintTrafficSummary(IEnumerable<string> outputLines)
    {
        var trafficLines = outputLines
            .Where(line => line.Contains("TRAFFIC up=", StringComparison.Ordinal))
            .TakeLast(3)
            .ToArray();

        if (trafficLines.Length == 0)
        {
            Console.WriteLine("traffic summary: no TRAFFIC status lines captured");
            return;
        }

        Console.WriteLine("traffic summary:");
        foreach (var line in trafficLines)
        {
            Console.WriteLine($"  {line}");
        }
    }

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
        foreach (var pattern in new[]
                 {
                     "TCP APP MATCH",
                     "REDIRECT TCP",
                     "PASS RELAY TCP OUT",
                     "PASS RELAY TCP IN",
                     "DIRECT TCP ACCEPT",
                     "DIRECT TCP CONNECT",
                     "DIRECT TCP SEND",
                     "DIRECT TCP RECV",
                     "DIRECT TCP END",
                     "RESTORE TCP RECV",
                     "DIRECT TCP failed",
                     "copy failed",
                     "UDP APP MATCH",
                     "REDIRECT UDP",
                     "DIRECT UDP SEND",
                     "DIRECT UDP RECV",
                     "RESTORE UDP RECV",
                     "DIRECT UDP send failed",
                     "UDP relay remote receive failed",
                     "No direct target",
                     "SendPacket"
                 })
        {
            var count = lines.Count(line => line.Contains(pattern, StringComparison.Ordinal));
            Console.WriteLine($"  {pattern}: {count}");
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
        return line.Contains("TCP APP MATCH", StringComparison.Ordinal)
            || line.Contains("REDIRECT TCP", StringComparison.Ordinal)
            || line.Contains("RESTORE TCP", StringComparison.Ordinal)
            || line.Contains("PASS RELAY TCP", StringComparison.Ordinal)
            || line.Contains("DIRECT TCP", StringComparison.Ordinal)
            || line.Contains("UDP APP MATCH", StringComparison.Ordinal)
            || line.Contains("REDIRECT UDP", StringComparison.Ordinal)
            || line.Contains("RESTORE UDP", StringComparison.Ordinal)
            || line.Contains("DIRECT UDP", StringComparison.Ordinal)
            || line.Contains("UDP relay", StringComparison.Ordinal)
            || line.Contains("failed", StringComparison.OrdinalIgnoreCase)
            || line.Contains("No direct target", StringComparison.Ordinal)
            || line.Contains("SendPacket", StringComparison.Ordinal);
    }
}
