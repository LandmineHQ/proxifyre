using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using ProxiFyre;

namespace TrafficTest;

internal static class WinDivertTcpProbe
{
    private static readonly IPEndPoint Remote = new(IPAddress.Parse("202.89.233.100"), 443);
    private const int CrossProcessClientPort = 45679;

    public static async Task<int> RunAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        using var client = new Socket(
            AddressFamily.InterNetwork,
            SocketType.Stream,
            ProtocolType.Tcp)
        {
            NoDelay = true
        };

        WinDivertNative.Configure(AppContext.BaseDirectory);
        using var handle = WinDivertPacketRouter.OpenNetworkHandle();
        var connectTask = client.ConnectAsync(Remote, timeout.Token).AsTask();
        var buffer = new byte[131072];
        uint clientSequence = 0;
        var synAckInjected = false;
        try
        {
            while (!connectTask.IsCompleted)
            {
                if (!WinDivertNative.TryReceive(
                        handle,
                        buffer,
                        out var packetLength,
                        out var address,
                        out var error))
                {
                    if (error is WinDivertNative.ErrorNoData or WinDivertNative.ErrorOperationAborted)
                    {
                        continue;
                    }

                    throw new Win32Exception(error);
                }

                if (!PacketView.TryParseIp(buffer.AsSpan(0, packetLength), packetLength, out var packet)
                    || !packet.IsTcp
                    || !packet.DestinationAddress.Equals(Remote.Address)
                    || packet.DestinationPort != Remote.Port)
                {
                    Pass(handle, buffer.AsSpan(0, packetLength), address);
                    continue;
                }

                if (packet.IsInitialSyn)
                {
                    clientSequence = packet.TcpSequenceNumber;
                    var interfaceIndex = address.NetworkInterfaceIndex;
                    if (interfaceIndex == 0)
                    {
                        interfaceIndex = (uint)NetworkInterfaceIndexResolver.FindBestInterfaceIndex(Remote.Address);
                    }

                    var serverSequence = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
                    var segment = new TcpSegment(
                        unchecked((uint)serverSequence),
                        clientSequence + 1,
                        PacketView.TcpFlagSyn | PacketView.TcpFlagAck,
                        65535,
                        0,
                        ReadOnlyMemory<byte>.Empty,
                        new byte[] { 2, 4, 0x05, 0xB4 });
                    var synAck = WinDivertPacketBuilder.BuildTcpSegment(
                        Remote.Address,
                        (ushort)Remote.Port,
                        packet.SourceAddress,
                        packet.SourcePort,
                        segment);
                    var inbound = WinDivertAddress.CreateInbound(
                        interfaceIndex,
                        address.NetworkSubInterfaceIndex,
                        ipv6: false);
                    if (!WinDivertNative.TrySend(handle, synAck, inbound, out var sendError))
                    {
                        throw new Win32Exception(sendError, "Synthetic SYN-ACK injection failed.");
                    }

                    Console.WriteLine($"SYN-ACK packet={Convert.ToHexString(synAck)}");
                    synAckInjected = true;
                    continue;
                }

                if ((packet.TcpFlags & PacketView.TcpFlagAck) != 0
                    && packet.TcpAcknowledgmentNumber != 0)
                {
                    continue;
                }

                Pass(handle, buffer.AsSpan(0, packetLength), address);
            }

            await connectTask.ConfigureAwait(false);
            Console.WriteLine(
                $"PASS: Windows accepted synthetic SYN-ACK for {Remote}; clientSequence=0x{clientSequence:X8}.");
            return 0;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine(
                $"FAIL: TCP connect did not complete after synthetic SYN-ACK injection (injected={synAckInjected}).");
            return 1;
        }
    }

    public static async Task<int> RunCrossProcessAsync()
    {
        var executable = Environment.ProcessPath
            ?? throw new InvalidOperationException("Current executable path is unavailable.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        using var child = Process.Start(new ProcessStartInfo
        {
            FileName = executable,
            Arguments = "windivert-tcp-probe-client",
            UseShellExecute = false,
            CreateNoWindow = true
        }) ?? throw new InvalidOperationException("Failed to start the cross-process TCP probe client.");

        WinDivertNative.Configure(AppContext.BaseDirectory);
        using var handle = WinDivertNative.Open(
            $"outbound and tcp and tcp.SrcPort == {CrossProcessClientPort} and tcp.DstPort == {Remote.Port}",
            WinDivertLayer.Network,
            priority: 0,
            WinDivertOpenFlags.Fragments);
        var buffer = new byte[131072];
        var injected = false;
        try
        {
            while (!child.HasExited)
            {
                if (!WinDivertNative.TryReceive(
                        handle,
                        buffer,
                        out var packetLength,
                        out var address,
                        out var error))
                {
                    if (error is WinDivertNative.ErrorNoData or WinDivertNative.ErrorOperationAborted)
                    {
                        continue;
                    }

                    throw new Win32Exception(error);
                }

                if (!PacketView.TryParseIp(buffer.AsSpan(0, packetLength), packetLength, out var packet)
                    || !packet.IsTcp
                    || packet.SourcePort != CrossProcessClientPort
                    || packet.DestinationPort != Remote.Port)
                {
                    continue;
                }

                if (packet.IsInitialSyn)
                {
                    var interfaceIndex = address.NetworkInterfaceIndex;
                    if (interfaceIndex == 0)
                    {
                        interfaceIndex = (uint)NetworkInterfaceIndexResolver.FindBestInterfaceIndex(Remote.Address);
                    }

                    var serverSequence = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
                    var synAck = WinDivertPacketBuilder.BuildTcpSegment(
                        Remote.Address,
                        (ushort)Remote.Port,
                        packet.SourceAddress,
                        packet.SourcePort,
                        new TcpSegment(
                            unchecked((uint)serverSequence),
                            packet.TcpSequenceNumber + 1,
                            PacketView.TcpFlagSyn | PacketView.TcpFlagAck,
                            65535,
                            0,
                            ReadOnlyMemory<byte>.Empty,
                            new byte[] { 2, 4, 0x05, 0xB4 }));
                    var inbound = WinDivertAddress.CreateInbound(
                        interfaceIndex,
                        address.NetworkSubInterfaceIndex,
                        ipv6: false);
                    if (!WinDivertNative.TrySend(handle, synAck, inbound, out var sendError))
                    {
                        throw new Win32Exception(sendError, "Cross-process SYN-ACK injection failed.");
                    }

                    injected = true;
                    continue;
                }

                if ((packet.TcpFlags & PacketView.TcpFlagAck) != 0)
                {
                    continue;
                }
            }

            await child.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            if (child.ExitCode == 0)
            {
                Console.WriteLine(
                    $"PASS: a separate client process accepted the synthetic SYN-ACK for {Remote} (injected={injected}).");
                return 0;
            }

            Console.Error.WriteLine(
                $"FAIL: cross-process client exited with {child.ExitCode} (injected={injected}).");
            return 1;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine(
                $"FAIL: cross-process TCP probe timed out (injected={injected}).");
            return 1;
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill(entireProcessTree: true);
            }
        }
    }

    public static async Task<int> RunClientAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(6));
        using var client = new Socket(
            AddressFamily.InterNetwork,
            SocketType.Stream,
            ProtocolType.Tcp);
        client.Bind(new IPEndPoint(IPAddress.Any, CrossProcessClientPort));
        try
        {
            await client.ConnectAsync(Remote, timeout.Token).ConfigureAwait(false);
            return 0;
        }
        catch
        {
            return 1;
        }
    }

    private static void Pass(
        WinDivertHandle handle,
        ReadOnlySpan<byte> packet,
        WinDivertAddress address)
    {
        if (!WinDivertNative.TrySend(handle, packet, address, out var error))
        {
            throw new Win32Exception(error, "Pass-through injection failed.");
        }
    }
}
