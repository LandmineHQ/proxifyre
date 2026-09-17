using System.IO.Pipes;
using System.Text;

namespace ProxiFyre;

/// <summary>
/// Module-side telemetry pipe client. It connects to the UI's telemetry pipe
/// and publishes one TrafficSnapshot per second. Connection is best-effort:
/// the client silently retries in the background, and relay operation never
/// depends on telemetry being available.
/// </summary>
internal sealed class TrafficTelemetryClient : IDisposable
{
    private readonly string _pipeName;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _sync = new();
    private NamedPipeClientStream? _stream;
    private StreamWriter? _writer;
    private long _sequence;
    private bool _disposed;

    public TrafficTelemetryClient(string pipeName)
    {
        _pipeName = pipeName;
    }

    public void Start()
    {
        _ = Task.Run(() => ReconnectLoopAsync(_cts.Token));
    }

    public void TryPublish(TrafficSnapshot snapshot)
    {
        lock (_sync)
        {
            if (_writer is null || _stream is not { IsConnected: true })
            {
                return;
            }

            try
            {
                _writer.WriteLine(TrafficTelemetryProtocol.Serialize(snapshot, ++_sequence));
            }
            catch
            {
                DisposeStreamLocked();
            }
        }
    }

    private async Task ReconnectLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (!IsConnectedLocked())
                {
                    await ConnectAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch
            {
                // Pipe is not available yet; retry on the next iteration.
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private async Task ConnectAsync(CancellationToken cancellationToken)
    {
        var stream = new NamedPipeClientStream(
            ".",
            _pipeName,
            PipeDirection.Out,
            PipeOptions.Asynchronous);

        await stream.ConnectAsync(TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(false);

        lock (_sync)
        {
            if (cancellationToken.IsCancellationRequested || _disposed)
            {
                stream.Dispose();
                return;
            }

            DisposeStreamLocked();
            _stream = stream;
            _writer = new StreamWriter(stream, Encoding.UTF8)
            {
                AutoFlush = true,
                NewLine = "\n"
            };
        }
    }

    private bool IsConnectedLocked()
    {
        lock (_sync)
        {
            return _stream is { IsConnected: true } && _writer is not null;
        }
    }

    private void DisposeStreamLocked()
    {
        _writer?.Dispose();
        _writer = null;
        _stream?.Dispose();
        _stream = null;
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            DisposeStreamLocked();
        }

        _cts.Cancel();
        _cts.Dispose();
    }
}

