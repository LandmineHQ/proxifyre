using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal sealed class WinDivertPacketInjector
{
    private readonly WinDivertHandle _handle;
    private readonly Action<string> _log;
    private readonly Action<string> _warningLog;
    private readonly DetailedLoggingState _detailedLogging;
    private long _tcpSendSucceeded;
    private long _tcpSendFailed;
    private long _udpSendSucceeded;
    private long _udpSendFailed;

    public WinDivertPacketInjector(
        WinDivertHandle handle,
        Action<string> log,
        bool detailedLogging,
        DetailedLoggingState? detailedLoggingState = null,
        Action<string>? warningLog = null)
    {
        _handle = handle;
        _log = log;
        _warningLog = warningLog ?? log;
        _detailedLogging = detailedLoggingState ?? new DetailedLoggingState(detailedLogging);
    }

    public long TcpSendSucceeded => Interlocked.Read(ref _tcpSendSucceeded);

    public long TcpSendFailed => Interlocked.Read(ref _tcpSendFailed);

    public long UdpSendSucceeded => Interlocked.Read(ref _udpSendSucceeded);

    public long UdpSendFailed => Interlocked.Read(ref _udpSendFailed);

    public bool InjectTcpSegment(DirectRelayTarget target, TcpSegment segment)
    {
        if (!TryGetEndpoints(
                target,
                out var clientAddress,
                out var remoteAddress,
                out var interfaceIndex,
                out var subInterfaceIndex))
        {
            if (_detailedLogging.Enabled)
            {
                _log(
                    $"WinDivert TCP injection could not resolve endpoints for {target.ClientEndpoint} <- {target.RemoteEndpoint}.");
            }

            return false;
        }

        try
        {
            var packet = WinDivertPacketBuilder.BuildTcpSegment(
                remoteAddress,
                target.RemotePort,
                clientAddress,
                target.ClientPort,
                segment);
            var address = WinDivertAddress.CreateInbound(
                interfaceIndex,
                subInterfaceIndex,
                ipv6: remoteAddress.AddressFamily == AddressFamily.InterNetworkV6);
            if (!WinDivertNative.TrySend(_handle, packet, address, out var error))
            {
                Interlocked.Increment(ref _tcpSendFailed);
                _log(
                    $"WinDivert TCP injection failed for {target.ClientEndpoint} <- {target.RemoteEndpoint}: {new System.ComponentModel.Win32Exception(error).Message}");
                return false;
            }

            Interlocked.Increment(ref _tcpSendSucceeded);
            if (_detailedLogging.Enabled
                && (segment.Flags & (PacketView.TcpFlagSyn | PacketView.TcpFlagAck))
                    == (PacketView.TcpFlagSyn | PacketView.TcpFlagAck))
            {
                _log(
                    $"WinDivert injected SYN-ACK {target.RemoteEndpoint} -> {target.ClientEndpoint} seq={segment.SequenceNumber} ack={segment.AcknowledgmentNumber} interface={interfaceIndex}.");
            }

            return true;
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _tcpSendFailed);
            _log(
                $"WinDivert TCP injection failed for {target.ClientEndpoint} <- {target.RemoteEndpoint}: {ex.Message}");
            return false;
        }
    }

    public bool InjectUdpResponse(
        DirectRelayTarget target,
        IPEndPoint remoteEndPoint,
        ReadOnlyMemory<byte> payload)
    {
        if (!TryGetEndpoints(
                target,
                out var clientAddress,
                out _,
                out var interfaceIndex,
                out var subInterfaceIndex))
        {
            return false;
        }

        var sourceAddress = MapAddressToFamily(remoteEndPoint.Address, clientAddress.AddressFamily);
        try
        {
            var packets = WinDivertPacketBuilder.BuildUdpFragments(
                sourceAddress,
                (ushort)remoteEndPoint.Port,
                clientAddress,
                target.ClientPort,
                payload.Span,
                target.AdapterMtu);
            var address = WinDivertAddress.CreateInbound(
                interfaceIndex,
                subInterfaceIndex,
                ipv6: clientAddress.AddressFamily == AddressFamily.InterNetworkV6);
            foreach (var packet in packets)
            {
                if (!WinDivertNative.TrySend(_handle, packet, address, out var error))
                {
                    Interlocked.Increment(ref _udpSendFailed);
                    _log(
                        $"WinDivert UDP injection failed for {target.ClientEndpoint} <- {remoteEndPoint}: {new System.ComponentModel.Win32Exception(error).Message}");
                    return false;
                }
            }

            Interlocked.Increment(ref _udpSendSucceeded);
            return true;
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _udpSendFailed);
            _log(
                $"WinDivert UDP injection failed for {target.ClientEndpoint} <- {remoteEndPoint}: {ex.Message}");
            return false;
        }
    }

    public void InjectUdpError(
        DirectRelayTarget target,
        IPEndPoint remoteEndPoint,
        ReadOnlyMemory<byte> originalPayload,
        SocketError socketError)
    {
        if (!TryGetEndpoints(
                target,
                out var clientAddress,
                out _,
                out var interfaceIndex,
                out var subInterfaceIndex))
        {
            return;
        }

        var remoteAddress = MapAddressToFamily(remoteEndPoint.Address, clientAddress.AddressFamily);
        try
        {
            var packet = WinDivertPacketBuilder.BuildUdpError(
                remoteAddress,
                (ushort)remoteEndPoint.Port,
                clientAddress,
                target.ClientPort,
                originalPayload.Span,
                socketError);
            var address = WinDivertAddress.CreateInbound(
                interfaceIndex,
                subInterfaceIndex,
                ipv6: clientAddress.AddressFamily == AddressFamily.InterNetworkV6);
            if (!WinDivertNative.TrySend(_handle, packet, address, out var error))
            {
                _log(
                    $"WinDivert UDP error injection failed for {target.ClientEndpoint} <- {remoteEndPoint}: {new System.ComponentModel.Win32Exception(error).Message}");
            }
        }
        catch (Exception ex)
        {
            _log(
                $"WinDivert UDP error injection failed for {target.ClientEndpoint} <- {remoteEndPoint}: {ex.Message}");
        }
    }

    private bool TryGetEndpoints(
        DirectRelayTarget target,
        out IPAddress clientAddress,
        out IPAddress remoteAddress,
        out uint interfaceIndex,
        out uint subInterfaceIndex)
    {
        clientAddress = IPAddress.None;
        remoteAddress = IPAddress.None;
        subInterfaceIndex = target.SubInterfaceIndex;
        interfaceIndex = target.InterfaceIndex > 0
            ? (uint)target.InterfaceIndex
            : 0;
        if (target.ClientAddress is null
            || target.ClientPort == 0
            || target.RemotePort == 0)
        {
            return false;
        }

        clientAddress = NetworkAddress.Normalize(target.ClientAddress);
        remoteAddress = NetworkAddress.Normalize(target.RemoteAddress);
        if (clientAddress.AddressFamily != remoteAddress.AddressFamily)
        {
            return false;
        }

        if (interfaceIndex == 0)
        {
            var resolved = NetworkInterfaceIndexResolver.FindBestInterfaceIndex(remoteAddress);
            interfaceIndex = resolved > 0 ? (uint)resolved : 0;
            if (interfaceIndex > 0)
            {
                _warningLog(
                    $"WinDivert packet injection fell back to best-interface lookup for {clientAddress} -> {remoteAddress}: interfaceIndex={interfaceIndex}.");
            }
        }

        return interfaceIndex > 0;
    }

    private static IPAddress MapAddressToFamily(IPAddress address, AddressFamily addressFamily)
    {
        if (addressFamily == AddressFamily.InterNetwork && address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return address.MapToIPv4();
        }

        if (addressFamily == AddressFamily.InterNetworkV6 && address.AddressFamily == AddressFamily.InterNetwork)
        {
            return address.MapToIPv6();
        }

        return address;
    }
}
