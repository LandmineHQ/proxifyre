using System.IO;
using System.IO.Pipes;
using System.Text;

namespace ProxiFyre;

/// <summary>
/// UI-side telemetry pipe server. The injected relay module connects to this
/// pipe and streams one TrafficSnapshot per second. This keeps high-frequency
/// network speed data out of the log files and off the WM_COPYDATA control channel.
/// </summary>
internal sealed class TrafficTelemetryServer : IDisposable
{
    private readonly Action<TrafficSnapshot> _onSnapshot;
    private readonly Action<string>? _log;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loopTask;
    private bool _disposed;

    public TrafficTelemetryServer(Action<TrafficSnapshot> onSnapshot, Action<string>? log = null)
    {
        _onSnapshot = onSnapshot;
        _log = log;
    }

    public string PipeName => TrafficTelemetryProtocol.PipeName;

    public void Start()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(TrafficTelemetryServer));
        }

        _loopTask = Task.Run(AcceptLoopAsync);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                // Default pipe DACL (same-user access) is sufficient: telemetry only
                // carries byte counters, and both UI and the relay module run as the
                // same Windows user.
                await using var server = new NamedPipeServerStream(
                    TrafficTelemetryProtocol.PipeName,
                    PipeDirection.In,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(_cts.Token).ConfigureAwait(false);
                await ReadLoopAsync(server).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_cts.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _log?.Invoke($"Traffic telemetry pipe error: {ex.Message}");
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), _cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    private async Task ReadLoopAsync(NamedPipeServerStream server)
    {
        using var reader = new StreamReader(server, Encoding.UTF8);
        while (!_cts.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(_cts.Token).ConfigureAwait(false);
            if (line is null)
            {
                return; // module disconnected; accept the next connection
            }

            if (TrafficTelemetryProtocol.TryParse(line, out _, out var snapshot))
            {
                _onSnapshot(snapshot);
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cts.Cancel();
        _cts.Dispose();
        _loopTask = null;
    }
}
