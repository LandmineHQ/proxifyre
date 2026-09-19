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
            $"seq={sequence} up={snapshot.UploadBytes} down={snapshot.DownloadBytes} upRate={snapshot.UploadBytesPerSecond} downRate={snapshot.DownloadBytesPerSecond} tcpUp={snapshot.TcpUploadBytes} tcpDown={snapshot.TcpDownloadBytes} tcpUpRate={snapshot.TcpUploadBytesPerSecond} tcpDownRate={snapshot.TcpDownloadBytesPerSecond} udpUp={snapshot.UdpUploadBytes} udpDown={snapshot.UdpDownloadBytes} udpUpRate={snapshot.UdpUploadBytesPerSecond} udpDownRate={snapshot.UdpDownloadBytesPerSecond}");
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
        long tcpUp = 0;
        long tcpDown = 0;
        long tcpUpRate = 0;
        long tcpDownRate = 0;
        long udpUp = 0;
        long udpDown = 0;
        long udpUpRate = 0;
        long udpDownRate = 0;
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
                case "tcpUp":
                    tcpUp = parsed;
                    break;
                case "tcpDown":
                    tcpDown = parsed;
                    break;
                case "tcpUpRate":
                    tcpUpRate = parsed;
                    break;
                case "tcpDownRate":
                    tcpDownRate = parsed;
                    break;
                case "udpUp":
                    udpUp = parsed;
                    break;
                case "udpDown":
                    udpDown = parsed;
                    break;
                case "udpUpRate":
                    udpUpRate = parsed;
                    break;
                case "udpDownRate":
                    udpDownRate = parsed;
                    break;
                default:
                    return false;
            }
        }

        if (!hasSequence)
        {
            return false;
        }

        snapshot = new TrafficSnapshot(
            up,
            down,
            upRate,
            downRate,
            tcpUp,
            tcpDown,
            tcpUpRate,
            tcpDownRate,
            udpUp,
            udpDown,
            udpUpRate,
            udpDownRate);
        return true;
    }
}
