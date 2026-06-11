namespace ProxiFyre;

internal sealed class TrafficCounter
{
    private long _uploadBytes;
    private long _downloadBytes;

    public void AddUpload(long bytes)
    {
        if (bytes > 0)
        {
            Interlocked.Add(ref _uploadBytes, bytes);
        }
    }

    public void AddDownload(long bytes)
    {
        if (bytes > 0)
        {
            Interlocked.Add(ref _downloadBytes, bytes);
        }
    }

    public TrafficSnapshot Snapshot(long previousUploadBytes = 0, long previousDownloadBytes = 0, double elapsedSeconds = 1)
    {
        var uploadBytes = Interlocked.Read(ref _uploadBytes);
        var downloadBytes = Interlocked.Read(ref _downloadBytes);
        var interval = elapsedSeconds <= 0 ? 1 : elapsedSeconds;
        return new TrafficSnapshot(
            uploadBytes,
            downloadBytes,
            (long)Math.Max(0, (uploadBytes - previousUploadBytes) / interval),
            (long)Math.Max(0, (downloadBytes - previousDownloadBytes) / interval));
    }
}

internal readonly record struct TrafficSnapshot(
    long UploadBytes,
    long DownloadBytes,
    long UploadBytesPerSecond,
    long DownloadBytesPerSecond)
{
    public static TrafficSnapshot Empty => new(0, 0, 0, 0);
}
