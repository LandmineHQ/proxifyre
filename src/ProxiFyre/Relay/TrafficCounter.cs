namespace ProxiFyre;

internal sealed class TrafficCounter
{
    private long _tcpUploadBytes;
    private long _tcpDownloadBytes;
    private long _udpUploadBytes;
    private long _udpDownloadBytes;

    public void AddTcpUpload(long bytes)
    {
        Add(ref _tcpUploadBytes, bytes);
    }

    public void AddTcpDownload(long bytes)
    {
        Add(ref _tcpDownloadBytes, bytes);
    }

    public void AddUdpUpload(long bytes)
    {
        Add(ref _udpUploadBytes, bytes);
    }

    public void AddUdpDownload(long bytes)
    {
        Add(ref _udpDownloadBytes, bytes);
    }

    public TrafficSnapshot Snapshot(TrafficSnapshot previous, double elapsedSeconds = 1)
    {
        var tcpUploadBytes = Interlocked.Read(ref _tcpUploadBytes);
        var tcpDownloadBytes = Interlocked.Read(ref _tcpDownloadBytes);
        var udpUploadBytes = Interlocked.Read(ref _udpUploadBytes);
        var udpDownloadBytes = Interlocked.Read(ref _udpDownloadBytes);
        var uploadBytes = tcpUploadBytes + udpUploadBytes;
        var downloadBytes = tcpDownloadBytes + udpDownloadBytes;
        var interval = elapsedSeconds <= 0 ? 1 : elapsedSeconds;
        return new TrafficSnapshot(
            uploadBytes,
            downloadBytes,
            Rate(uploadBytes, previous.UploadBytes, interval),
            Rate(downloadBytes, previous.DownloadBytes, interval),
            tcpUploadBytes,
            tcpDownloadBytes,
            Rate(tcpUploadBytes, previous.TcpUploadBytes, interval),
            Rate(tcpDownloadBytes, previous.TcpDownloadBytes, interval),
            udpUploadBytes,
            udpDownloadBytes,
            Rate(udpUploadBytes, previous.UdpUploadBytes, interval),
            Rate(udpDownloadBytes, previous.UdpDownloadBytes, interval));
    }

    private static void Add(ref long counter, long bytes)
    {
        if (bytes > 0)
        {
            Interlocked.Add(ref counter, bytes);
        }
    }

    private static long Rate(long current, long previous, double elapsedSeconds)
    {
        return (long)Math.Max(0, (current - previous) / elapsedSeconds);
    }
}

internal readonly record struct TrafficSnapshot(
    long UploadBytes,
    long DownloadBytes,
    long UploadBytesPerSecond,
    long DownloadBytesPerSecond,
    long TcpUploadBytes,
    long TcpDownloadBytes,
    long TcpUploadBytesPerSecond,
    long TcpDownloadBytesPerSecond,
    long UdpUploadBytes,
    long UdpDownloadBytes,
    long UdpUploadBytesPerSecond,
    long UdpDownloadBytesPerSecond)
{
    public TrafficSnapshot(
        long uploadBytes,
        long downloadBytes,
        long uploadBytesPerSecond,
        long downloadBytesPerSecond)
        : this(
            uploadBytes,
            downloadBytes,
            uploadBytesPerSecond,
            downloadBytesPerSecond,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0)
    {
    }

    public static TrafficSnapshot Empty => new(0, 0, 0, 0);
}
