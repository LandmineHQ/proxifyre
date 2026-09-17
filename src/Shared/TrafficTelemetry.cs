using System.Globalization;

namespace ProxiFyre;

/// <summary>
/// Wire protocol for the high-frequency traffic telemetry channel.
/// Telemetry is streamed over a named pipe as compact single-line
/// key=value messages and is intentionally kept out of the log files.
/// </summary>
internal static class TrafficTelemetryProtocol
{
    public const string PipeName = "ProxiFyre.Telemetry.v1";

    public static string Serialize(TrafficSnapshot snapshot, long sequence)
    {
        return string.Create(
            CultureInfo.InvariantCulture,
            $"seq={sequence} up={snapshot.UploadBytes} down={snapshot.DownloadBytes} upRate={snapshot.UploadBytesPerSecond} downRate={snapshot.DownloadBytesPerSecond}");
    }

    public static bool TryParse(string line, out long sequence, out TrafficSnapshot snapshot)
    {
        sequence = 0;
        snapshot = default;
        if (string.IsNullOrWhiteSpace(line))
        {
            return false;
        }

        long up = 0;
        long down = 0;
        long upRate = 0;
        long downRate = 0;
        var hasSequence = false;

        foreach (var part in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = part.IndexOf('=');
            if (separator <= 0 || separator == part.Length - 1)
            {
                return false;
            }

            var key = part[..separator];
            var value = part[(separator + 1)..];
            if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            {
                return false;
            }

            switch (key)
            {
                case "seq":
                    sequence = parsed;
                    hasSequence = true;
                    break;
                case "up":
                    up = parsed;
                    break;
                case "down":
                    down = parsed;
                    break;
                case "upRate":
                    upRate = parsed;
                    break;
                case "downRate":
                    downRate = parsed;
                    break;
                default:
                    return false;
            }
        }

        if (!hasSequence)
        {
            return false;
        }

        snapshot = new TrafficSnapshot(up, down, upRate, downRate);
        return true;
    }
}
