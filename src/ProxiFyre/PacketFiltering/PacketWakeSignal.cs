namespace ProxiFyre;

internal sealed class PacketWakeSignal : IDisposable
{
    private readonly AutoResetEvent _event = new(false);
    private bool _disposed;

    public WaitHandle WaitHandle => _event;

    public void Pulse()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            _event.Set();
        }
        catch (ObjectDisposedException)
        {
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _event.Dispose();
    }
}
