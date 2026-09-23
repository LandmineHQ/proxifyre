using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal sealed class WinDivertUdpRelay : IDisposable
{
    private readonly DynamicAppConfiguration _configuration;
    private readonly ProcessLookup _processLookup;
    private readonly UdpDirectRelay _relay;
    private readonly WinDivertPacketInjector _injector;
    private readonly Action<string> _log;
    private readonly bool _detailedLogging;
    private readonly TimeProvider _timeProvider;
    private readonly ConcurrentDictionary<UdpRelayKey, byte> _activeFlows = new();
    private readonly ConcurrentDictionary<string, long> _throttledLogTimes = new();
    private bool _disposed;

    public WinDivertUdpRelay(
        DynamicAppConfiguration configuration,
        ProcessLookup processLookup,
        WinDivertPacketInjector injector,
        Action<string> log,
        TrafficCounter trafficCounter,
        PacketWakeSignal packetWakeSignal,
        TimeProvider timeProvider,
        bool detailedLogging)
    {
        _configuration = configuration;
        _processLookup = processLookup;
        _injector = injector;
        _log = log;
        _detailedLogging = detailedLogging;
        _timeProvider = timeProvider;
        _relay = new UdpDirectRelay(log, detailedLogging, trafficCounter, packetWakeSignal, timeProvider);
        _relay.SetResponseInjector(InjectResponse);
        _relay.SetErrorInjector(InjectError);
        _relay.SetResponseValidator(IsTargetCurrent);
        _relay.SetOutboundBypass(static _ => { }, static _ => { });
        _relay.SetTargetRedirectUnregister(static _ => { });
    }

    public void Start(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _relay.Start(cancellationToken);
    }

    public bool TryHandlePacket(
        PacketView packet,
        uint interfaceIndex,
        uint subInterfaceIndex,
        ProcessInfo process,
        string? matchedPattern,
        long captureTimestamp,
        long processResolvedTimestamp,
        out bool createdFlow)
    {
        createdFlow = false;
        if (interfaceIndex == 0)
        {
            LogThrottled(
                "unresolved-interface",
                $"WinDivert UDP relay dropped unresolved-interface flow for {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}.");
            return false;
        }

        var key = CreateRelayKey(packet, interfaceIndex, subInterfaceIndex, process.ProcessId);
        createdFlow = _activeFlows.TryAdd(key, 0);
        if (createdFlow)
        {
            _log(
                $"APP UDP CONNECT pid={process.ProcessId} local={packet.SourceAddress}:{packet.SourcePort} target={packet.DestinationAddress}:{packet.DestinationPort} payloadBytes={packet.UdpPayload.Length} pattern={matchedPattern}");
        }

        var targetStartedTimestamp = Stopwatch.GetTimestamp();
        var target = CreateTarget(
            packet,
            interfaceIndex,
            subInterfaceIndex,
            process,
            matchedPattern);
        var targetReadyTimestamp = Stopwatch.GetTimestamp();
        if (!_relay.TrySubmit(
                key,
                target,
                packet.UdpPayload.ToArray(),
                packet.DestinationAddress,
                packet.DestinationPort,
                out var failureReason,
                out var retryable))
        {
            if (!retryable)
            {
                _relay.Remove(key);
                _activeFlows.TryRemove(key, out _);
            }
            else
            {
                // Keep the flow on one path: stop the saturated relay session
                // and let this and subsequent datagrams pass through directly.
                _relay.Remove(key);
                _activeFlows.TryRemove(key, out _);
                _relay.MarkBypassedFlow(key);
            }

            LogThrottled(
                "submit-failure",
                $"WinDivert UDP relay rejected packet for {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}: {failureReason}");
            return false;
        }

        if (createdFlow && _detailedLogging)
        {
            var submittedTimestamp = Stopwatch.GetTimestamp();
            _log(
                $"UDP relay timing resolveMs={Stopwatch.GetElapsedTime(captureTimestamp, processResolvedTimestamp).TotalMilliseconds:F2} targetMs={Stopwatch.GetElapsedTime(targetStartedTimestamp, targetReadyTimestamp).TotalMilliseconds:F2} submitMs={Stopwatch.GetElapsedTime(targetReadyTimestamp, submittedTimestamp).TotalMilliseconds:F2} totalMs={Stopwatch.GetElapsedTime(captureTimestamp, submittedTimestamp).TotalMilliseconds:F2}");
        }

        return true;
    }

    public bool HasTarget(UdpRelayKey key)
    {
        return _relay.TryGetTarget(key, out _);
    }

    public bool IsRelayOutboundFlow(UdpRelayKey key)
    {
        return _relay.IsRelayOutboundFlow(key);
    }

    public bool IsBypassedFlow(UdpRelayKey key)
    {
        return _relay.IsBypassedFlow(key);
    }

    public void ApplyConfiguration(AppConfiguration configuration)
    {
        _relay.ApplyConfiguration(configuration);
        foreach (var key in _activeFlows.Keys)
        {
            if (!_relay.TryGetTarget(key, out _))
            {
                _activeFlows.TryRemove(key, out _);
            }
        }
    }

    public void Remove(UdpRelayKey key)
    {
        _relay.Remove(key);
        _activeFlows.TryRemove(key, out _);
    }

    private bool InjectResponse(
        DirectRelayTarget target,
        IPEndPoint remoteEndPoint,
        ReadOnlyMemory<byte> payload)
    {
        return _injector.InjectUdpResponse(target, remoteEndPoint, payload);
    }

    private void InjectError(
        DirectRelayTarget target,
        IPEndPoint remoteEndPoint,
        ReadOnlyMemory<byte> originalPayload,
        SocketError socketError)
    {
        _injector.InjectUdpError(target, remoteEndPoint, originalPayload, socketError);
    }

    private bool IsTargetCurrent(DirectRelayTarget target)
    {
        var process = _processLookup.GetProcessInfo(target.ProcessId);
        return process is not null
            && process.Name.Equals(target.ProcessName, StringComparison.OrdinalIgnoreCase)
            && process.Path.Equals(target.ProcessPath, StringComparison.OrdinalIgnoreCase)
            && _processLookup.ValidateProcessIdentity(
                target.ProcessId,
                target.ProcessStartTimeUtcTicks)
            && _configuration.Current.TryGetMatchingPattern(process, out _, out _);
    }

    private DirectRelayTarget CreateTarget(
        PacketView packet,
        uint interfaceIndex,
        uint subInterfaceIndex,
        ProcessInfo process,
        string? matchedPattern)
    {
        var mtu = NetworkInterfaceIndexResolver.TryGetMtu(
            (int)interfaceIndex,
            packet.AddressFamily,
            out var resolvedMtu)
            ? resolvedMtu
            : 1500;
        return new DirectRelayTarget(
            packet.DestinationAddress,
            packet.DestinationPort,
            _timeProvider.GetUtcNow(),
            process.ProcessId,
            process.Name,
            process.Path,
            matchedPattern ?? string.Empty,
            packet.SourceAddress,
            packet.SourcePort,
            new IntPtr(interfaceIndex),
            AdapterMtu: mtu,
            InterfaceIndex: (int)interfaceIndex,
            SubInterfaceIndex: subInterfaceIndex,
            WireAddressFamily: (ushort)(packet.AddressFamily == AddressFamily.InterNetwork ? 2 : 23),
            ProcessStartTimeUtcTicks: process.StartTimeUtcTicks);
    }

    private static UdpRelayKey CreateRelayKey(
        PacketView packet,
        uint interfaceIndex,
        uint subInterfaceIndex,
        int processId)
    {
        return new UdpRelayKey(
            new IntPtr(interfaceIndex),
            0,
            packet.SourceAddress,
            packet.SourcePort,
            packet.DestinationAddress,
            packet.DestinationPort,
            subInterfaceIndex,
            compartmentId: 0,
            (ushort)(packet.AddressFamily == AddressFamily.InterNetwork ? 2 : 23),
            (uint)processId,
            flowId: 0);
    }

    private void LogThrottled(string category, string message)
    {
        var now = Environment.TickCount64;
        if (_throttledLogTimes.TryGetValue(category, out var last) && now - last < 5000)
        {
            return;
        }

        _throttledLogTimes[category] = now;
        _log(message);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _activeFlows.Clear();
        _relay.Dispose();
    }
}
