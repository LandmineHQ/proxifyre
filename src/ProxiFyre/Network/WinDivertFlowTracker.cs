using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;

namespace ProxiFyre;

internal readonly record struct WinDivertFlowKey(
    byte Protocol,
    IPAddress LocalAddress,
    ushort LocalPort,
    IPAddress RemoteAddress,
    ushort RemotePort)
{
    public static WinDivertFlowKey FromPacket(PacketView packet)
    {
        return new WinDivertFlowKey(
            packet.Protocol,
            NetworkAddress.Normalize(packet.SourceAddress),
            packet.SourcePort,
            NetworkAddress.Normalize(packet.DestinationAddress),
            packet.DestinationPort);
    }

    public static WinDivertFlowKey FromAddress(WinDivertAddress address)
    {
        return new WinDivertFlowKey(
            address.Protocol,
            NetworkAddress.Normalize(address.LocalAddress),
            address.LocalPort,
            NetworkAddress.Normalize(address.RemoteAddress),
            address.RemotePort);
    }
}

internal sealed class WinDivertFlowTracker : IDisposable
{
    private const int MaxTrackedFlows = 32768;
    private readonly ConcurrentDictionary<WinDivertFlowKey, FlowOwner> _flows = new();
    private readonly ProcessLookup _processLookup;
    private readonly Action<string> _log;
    private readonly CancellationTokenSource _cts = new();
    private WinDivertHandle? _handle;
    private Task? _loopTask;
    private bool _disposed;

    public WinDivertFlowTracker(
        ProcessLookup processLookup,
        Action<string> log,
        WinDivertHandle? handle = null)
    {
        _processLookup = processLookup;
        _log = log;
        _handle = handle;
    }

    public bool IsAvailable => _handle is not null;

    public static WinDivertHandle OpenHandle()
    {
        var handle = WinDivertNative.Open(
            "event == ESTABLISHED or event == DELETED",
            WinDivertLayer.Flow,
            priority: 0,
            WinDivertOpenFlags.Sniff | WinDivertOpenFlags.ReceiveOnly);
        ConfigureQueue(handle);
        return handle;
    }

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_loopTask is not null)
        {
            return;
        }

        try
        {
            _handle ??= OpenHandle();
            _loopTask = Task.Factory.StartNew(
                () => ReceiveLoop(_cts.Token),
                _cts.Token,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
            _log("WinDivert flow tracker started.");
        }
        catch (Exception ex) when (ex is Win32Exception or FileNotFoundException or DllNotFoundException)
        {
            _handle?.Dispose();
            _handle = null;
            _log(
                $"WinDivert flow tracker is unavailable; process-table fallback will be used: {ex.Message}");
        }
    }

    private static void ConfigureQueue(WinDivertHandle handle)
    {
        _ = WinDivertNative.TrySetParameter(handle, WinDivertParameter.QueueLength, 16384);
        _ = WinDivertNative.TrySetParameter(handle, WinDivertParameter.QueueTime, 2000);
    }

    public bool TryGetProcessId(PacketView packet, out uint processId)
    {
        processId = 0;
        if (!_flows.TryGetValue(WinDivertFlowKey.FromPacket(packet), out var owner))
        {
            return false;
        }

        if (owner.ProcessId == (uint)Environment.ProcessId)
        {
            processId = owner.ProcessId;
            return true;
        }

        var process = _processLookup.GetProcessInfo((int)owner.ProcessId);
        if (process is null
            || (owner.ProcessStartTimeUtcTicks != 0
                && process.StartTimeUtcTicks != owner.ProcessStartTimeUtcTicks))
        {
            _flows.TryRemove(WinDivertFlowKey.FromPacket(packet), out _);
            return false;
        }

        processId = (uint)owner.ProcessId;
        return true;
    }

    private void ReceiveLoop(CancellationToken cancellationToken)
    {
        var handle = _handle!;
        var buffer = new byte[64];
        while (!cancellationToken.IsCancellationRequested)
        {
            if (!WinDivertNative.TryReceive(
                    handle,
                    buffer,
                    out _,
                    out var address,
                    out var error))
            {
                if (cancellationToken.IsCancellationRequested
                    || error is WinDivertNative.ErrorNoData or WinDivertNative.ErrorOperationAborted)
                {
                    return;
                }

                _log($"WinDivert flow receive failed: {new Win32Exception(error).Message}");
                Thread.Sleep(10);
                continue;
            }

            if (address.Layer != WinDivertLayer.Flow
                || !address.IsOutbound
                || address.Protocol is not (PacketView.ProtocolTcp or PacketView.ProtocolUdp))
            {
                continue;
            }

            var key = WinDivertFlowKey.FromAddress(address);
            switch (address.Event)
            {
                case WinDivertEvent.FlowEstablished:
                    TrackFlow(key, address.ProcessId, address.Timestamp);
                    break;
                case WinDivertEvent.FlowDeleted:
                    _flows.TryRemove(key, out _);
                    break;
            }
        }
    }

    private void TrackFlow(WinDivertFlowKey key, uint processId, long eventTimestamp)
    {
        if (processId == 0)
        {
            return;
        }

        if (_flows.Count >= MaxTrackedFlows && !_flows.ContainsKey(key))
        {
            _log($"WinDivert flow tracker limit reached ({MaxTrackedFlows}); new process association was ignored.");
            return;
        }

        if (processId == (uint)Environment.ProcessId)
        {
            _flows[key] = new FlowOwner(processId, 0);
            return;
        }

        var process = _processLookup.GetProcessInfo((int)processId, forceRefresh: true);
        if (process is null || process.StartTimeUtcTicks == 0)
        {
            return;
        }

        var eventTime = GetEventTimeUtc(eventTimestamp);
        if (eventTime is null)
        {
            return;
        }

        if (process.StartTimeUtcTicks > eventTime.Value.AddSeconds(2).Ticks)
        {
            return;
        }

        _flows[key] = new FlowOwner(
            processId,
            process.StartTimeUtcTicks);
    }

    private static DateTimeOffset? GetEventTimeUtc(long eventTimestamp)
    {
        if (eventTimestamp <= 0 || Stopwatch.Frequency <= 0)
        {
            return null;
        }

        var elapsedSeconds =
            (eventTimestamp - Stopwatch.GetTimestamp()) / (double)Stopwatch.Frequency;
        return DateTimeOffset.UtcNow.AddSeconds(elapsedSeconds);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cts.Cancel();
        if (_handle is not null)
        {
            WinDivertNative.ShutdownReceive(_handle);
        }

        try
        {
            _loopTask?.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
        }

        _handle?.Dispose();
        _handle = null;
        _cts.Dispose();
        _flows.Clear();
    }

    private sealed record FlowOwner(uint ProcessId, long ProcessStartTimeUtcTicks);
}
