using System.Diagnostics;

namespace TrafficTest;

internal static class ProcessRunner
{
    public static Process Start(
        string fileName,
        string arguments,
        string workingDirectory,
        bool redirect,
        bool clearProxyEnvironment = false)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = redirect,
            RedirectStandardError = redirect
        };

        if (clearProxyEnvironment)
        {
            foreach (var key in new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy" })
            {
                startInfo.Environment.Remove(key);
            }
        }

        var process = new Process
        {
            StartInfo = startInfo,
            EnableRaisingEvents = true
        };

        if (!process.Start())
        {
            process.Dispose();
            throw new InvalidOperationException($"Failed to start {fileName}.");
        }

        return process;
    }

    public static Task CaptureProcessOutputAsync(Process process, BoundedLog output, bool echo, CancellationToken cancellationToken)
    {
        var stdout = Task.Run(() => CaptureReaderAsync("core>", process.StandardOutput, output, echo, cancellationToken), cancellationToken);
        var stderr = Task.Run(() => CaptureReaderAsync("core!", process.StandardError, output, echo, cancellationToken), cancellationToken);
        return Task.WhenAll(stdout, stderr);
    }

    public static async Task CaptureChildLinesAsync(StreamReader reader, List<string> lines, string echoPrefix)
    {
        while (await reader.ReadLineAsync() is { } line)
        {
            lock (lines)
            {
                lines.Add(line);
            }

            if (!string.IsNullOrWhiteSpace(line))
            {
                Console.WriteLine($"{echoPrefix} {line}");
            }
        }
    }

    public static string QuoteArgument(string argument)
    {
        if (argument.Length == 0)
        {
            return "\"\"";
        }

        return argument.Any(char.IsWhiteSpace) || argument.Contains('"', StringComparison.Ordinal)
            ? "\"" + argument.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\""
            : argument;
    }

    private static async Task CaptureReaderAsync(
        string prefix,
        StreamReader reader,
        BoundedLog output,
        bool echo,
        CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(cancellationToken);
                if (line is null)
                {
                    return;
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                var formatted = $"{prefix} {line}";
                output.Add(formatted);
                if (echo)
                {
                    Console.WriteLine(formatted);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch
        {
        }
    }
}
