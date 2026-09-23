using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ProxiFyre;

namespace TrafficTest;

internal static class PacketSelfTest
{
    public static int Run()
    {
        try
        {
            TestUdpParsingAndDeclaredLength();
            TestMulticastDetection();
            TestVlanParsing();
            TestTcpOptionsAndUrgentPointer();
            TestWinDivertPacketBuilders();
            TestWinDivertTcpPacketBuilder();
            TestWinDivertUdpErrorBuilder();
            TestWinDivertUdpFragmentation();
            TestTrafficCounterBreakdown();
            TestWinDivertAddressLayout();
            TestUuPatchProfileCatalog();
            TestUuPatchPersistence();
            TestDisabledApplicationPersistence();
            TestModuleMessageProtocol();
            TestNetworkInterfaceIndexResolution();
            TestRuntimeModuleCopy();
            Console.WriteLine("PASS: packet parsing, multicast detection, VLAN, TCP fields, WinDivert layouts/builders, TCP/UDP traffic counters, UU patch profiles/config, interface indexes, and runtime module copies.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAIL: {ex}");
            return 1;
        }
    }

    private static void TestUdpParsingAndDeclaredLength()
    {
        var payload = "udp-payload"u8.ToArray();
        var packet = BuildIpv4Packet(
            IPAddress.Parse("192.0.2.10"),
            IPAddress.Parse("198.51.100.20"),
            PacketView.ProtocolUdp,
            12345,
            53,
            payload,
            declaredTransportLength: 8 + payload.Length);

        Assert(PacketView.TryParse(packet, packet.Length, out var view), "IPv4 UDP packet did not parse.");
        Assert(view.SourcePort == 12345, "UDP source port mismatch.");
        Assert(view.DestinationPort == 53, "UDP destination port mismatch.");
        Assert(view.UdpLength == 8 + payload.Length, "UDP declared length mismatch.");
        Assert(view.UdpPayload.SequenceEqual(payload), "UDP payload should use the declared UDP length.");
    }

    private static void TestTrafficCounterBreakdown()
    {
        var counter = new TrafficCounter();
        counter.AddTcpUpload(1000);
        counter.AddTcpDownload(2000);
        counter.AddUdpUpload(3000);
        counter.AddUdpDownload(4000);

        var first = counter.Snapshot(TrafficSnapshot.Empty, elapsedSeconds: 1);
        Assert(first.UploadBytes == 4000, "TCP/UDP upload totals mismatch.");
        Assert(first.DownloadBytes == 6000, "TCP/UDP download totals mismatch.");
        Assert(first.TcpUploadBytes == 1000 && first.TcpDownloadBytes == 2000, "TCP traffic counters mismatch.");
        Assert(first.UdpUploadBytes == 3000 && first.UdpDownloadBytes == 4000, "UDP traffic counters mismatch.");

        counter.AddTcpUpload(500);
        counter.AddUdpDownload(1000);
        var second = counter.Snapshot(first, elapsedSeconds: 0.5);
        Assert(second.TcpUploadBytesPerSecond == 1000, "TCP upload rate mismatch.");
        Assert(second.UdpDownloadBytesPerSecond == 2000, "UDP download rate mismatch.");
    }

    private static void TestVlanParsing()
    {
        var payload = "vlan"u8.ToArray();
        var basePacket = BuildIpv4Packet(
            IPAddress.Parse("192.0.2.11"),
            IPAddress.Parse("198.51.100.21"),
            PacketView.ProtocolUdp,
            1000,
            2000,
            payload);
        var vlanPacket = new byte[basePacket.Length + 4];
        basePacket.AsSpan(0, 12).CopyTo(vlanPacket);
        BinaryPrimitives.WriteUInt16BigEndian(vlanPacket.AsSpan(12, 2), PacketView.EtherTypeVlan);
        BinaryPrimitives.WriteUInt16BigEndian(vlanPacket.AsSpan(14, 2), 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(vlanPacket.AsSpan(16, 2), PacketView.EtherTypeIpv4);
        basePacket.AsSpan(14).CopyTo(vlanPacket.AsSpan(18));

        Assert(PacketView.TryParse(vlanPacket, vlanPacket.Length, out var view), "VLAN IPv4 packet did not parse.");
        Assert(view.LinkHeaderLength == 18, "VLAN link header length mismatch.");
        Assert(view.UdpPayload.SequenceEqual(payload), "VLAN UDP payload mismatch.");
    }

    private static void TestMulticastDetection()
    {
        var ipv4Packet = BuildIpv4Packet(
            IPAddress.Parse("192.0.2.60"),
            IPAddress.Parse("224.0.0.251"),
            PacketView.ProtocolUdp,
            5353,
            5353,
            "mdns"u8.ToArray());
        Assert(PacketView.TryParse(ipv4Packet, ipv4Packet.Length, out var ipv4View), "IPv4 multicast packet did not parse.");
        Assert(ipv4View.IsNetworkLayerBroadcastOrMulticast(), "IPv4 multicast destination was not detected.");

        var ipv6Packet = BuildIpv6Packet(
            IPAddress.Parse("2001:db8::60"),
            IPAddress.Parse("ff02::fb"),
            PacketView.ProtocolUdp,
            5353,
            5353,
            "mdns"u8.ToArray());
        Assert(PacketView.TryParse(ipv6Packet, ipv6Packet.Length, out var ipv6View), "IPv6 multicast packet did not parse.");
        Assert(ipv6View.IsNetworkLayerBroadcastOrMulticast(), "IPv6 multicast destination was not detected.");
    }

    private static void TestTcpOptionsAndUrgentPointer()
    {
        var packet = BuildIpv4Packet(
            IPAddress.Parse("192.0.2.12"),
            IPAddress.Parse("198.51.100.22"),
            PacketView.ProtocolTcp,
            8080,
            443,
            [],
            tcpOptions: [2, 4, 0x05, 0xB4],
            tcpFlags: PacketView.TcpFlagUrg | PacketView.TcpFlagAck,
            urgentPointer: 7);

        Assert(PacketView.TryParse(packet, packet.Length, out var view), "IPv4 TCP packet did not parse.");
        Assert(view.TcpOptions.SequenceEqual(new byte[] { 2, 4, 0x05, 0xB4 }), "TCP options mismatch.");
        Assert(view.TcpUrgentPointer == 7, "TCP urgent pointer mismatch.");
        Assert((view.TcpFlags & PacketView.TcpFlagUrg) != 0, "TCP URG flag mismatch.");
    }

    private static void TestWinDivertPacketBuilders()
    {
        var payload = "windivert-udp"u8.ToArray();
        AssertWinDivertUdpPacket(
            WinDivertPacketBuilder.BuildUdpResponse(
                IPAddress.Parse("198.51.100.20"),
                443,
                IPAddress.Parse("192.0.2.10"),
                50000,
                payload),
            payload);
        AssertWinDivertUdpPacket(
            WinDivertPacketBuilder.BuildUdpResponse(
                IPAddress.Parse("2001:db8::20"),
                443,
                IPAddress.Parse("2001:db8::10"),
                50000,
                payload),
            payload);
        AssertThrows<ArgumentOutOfRangeException>(
            () => WinDivertPacketBuilder.BuildUdpResponse(
                IPAddress.Parse("198.51.100.20"),
                443,
                IPAddress.Parse("192.0.2.10"),
                50000,
                new byte[65508]),
            "Oversized IPv4 UDP payload was accepted.");
        AssertThrows<ArgumentOutOfRangeException>(
            () => WinDivertPacketBuilder.BuildUdpResponse(
                IPAddress.Parse("2001:db8::20"),
                443,
                IPAddress.Parse("2001:db8::10"),
                50000,
                new byte[65528]),
            "Oversized IPv6 UDP payload was accepted.");
    }

    private static void AssertWinDivertUdpPacket(
        byte[] ipPacket,
        byte[] expectedPayload)
    {
        Assert(PacketView.TryParseIp(ipPacket, ipPacket.Length, out var view), "WinDivert UDP packet did not parse.");
        Assert(view.SourcePort == 443 && view.DestinationPort == 50000, "WinDivert UDP packet ports mismatch.");
        Assert(view.UdpPayload.SequenceEqual(expectedPayload), "WinDivert UDP packet payload mismatch.");
    }

    private static void TestWinDivertAddressLayout()
    {
        Assert(Marshal.SizeOf<WinDivertAddress>() == 80, "WinDivert address layout must be 80 bytes.");
        var address = WinDivertAddress.CreateInbound(
            interfaceIndex: 17,
            subInterfaceIndex: 3,
            ipv6: true);
        Assert(address.Layer == WinDivertLayer.Network, "WinDivert address layer mismatch.");
        Assert(address.Event == WinDivertEvent.NetworkPacket, "WinDivert address event mismatch.");
        Assert(!address.IsOutbound, "WinDivert inbound address was marked outbound.");
        Assert(address.IsIpv6, "WinDivert IPv6 flag mismatch.");
        Assert(address.NetworkInterfaceIndex == 17, "WinDivert interface index mismatch.");
        Assert(address.NetworkSubInterfaceIndex == 3, "WinDivert sub-interface index mismatch.");
    }

    private static void TestWinDivertTcpPacketBuilder()
    {
        var sourceAddress = IPAddress.Parse("202.89.233.101");
        var destinationAddress = IPAddress.Parse("192.168.31.43");
        var segment = new TcpSegment(
            SequenceNumber: 0x8A4B2C1D,
            AcknowledgmentNumber: 0x27D5F3C8,
            PacketView.TcpFlagSyn | PacketView.TcpFlagAck,
            Window: 65535,
            UrgentPointer: 0,
            Payload: ReadOnlyMemory<byte>.Empty,
            Options: new byte[] { 2, 4, 0x05, 0xB4 });

        var packet = WinDivertPacketBuilder.BuildTcpSegment(
            sourceAddress,
            sourcePort: 443,
            destinationAddress,
            destinationPort: 55544,
            segment);
        Assert(PacketView.TryParseIp(packet, packet.Length, out var view), "WinDivert TCP packet did not parse.");
        Assert(view.SourcePort == 443 && view.DestinationPort == 55544, "WinDivert TCP ports mismatch.");
        Assert(view.TcpFlags == (PacketView.TcpFlagSyn | PacketView.TcpFlagAck), "WinDivert TCP flags mismatch.");
        Assert(view.TcpSequenceNumber == segment.SequenceNumber, "WinDivert TCP sequence mismatch.");
        Assert(view.TcpAcknowledgmentNumber == segment.AcknowledgmentNumber, "WinDivert TCP acknowledgement mismatch.");
        Assert(ComputeChecksum(packet.AsSpan(0, 20)) == 0, "WinDivert IPv4 header checksum is invalid.");
        Assert(
            ComputeTransportChecksum(
                sourceAddress,
                destinationAddress,
                PacketView.ProtocolTcp,
                packet.AsSpan(20)) == 0,
            "WinDivert TCP checksum is invalid.");

        var sourceV6 = IPAddress.Parse("2001:db8::20");
        var destinationV6 = IPAddress.Parse("2001:db8::10");
        var packetV6 = WinDivertPacketBuilder.BuildTcpSegment(
            sourceV6,
            sourcePort: 443,
            destinationV6,
            destinationPort: 55544,
            segment);
        Assert(
            PacketView.TryParseIp(packetV6, packetV6.Length, out var viewV6),
            "WinDivert IPv6 TCP packet did not parse.");
        Assert(
            viewV6.TcpFlags == (PacketView.TcpFlagSyn | PacketView.TcpFlagAck),
            "WinDivert IPv6 TCP flags mismatch.");
        Assert(
            ComputeTransportChecksum(
                sourceV6,
                destinationV6,
                PacketView.ProtocolTcp,
                packetV6.AsSpan(40)) == 0,
            "WinDivert IPv6 TCP checksum is invalid.");
    }

    private static void TestUuPatchProfileCatalog()
    {
        var repositoryRoot = RepositoryPaths.FindRepositoryRoot(AppContext.BaseDirectory);
        var catalogPath = Path.Combine(repositoryRoot, "src", "Shared", "UuPatchProfiles.json");
        var profiles = UuPatchCatalog.Load(catalogPath);
        Assert(profiles.Count == 1, "UU patch profile catalog should only contain the current supported profile.");

        var current = profiles.Single(profile => profile.Key == "uu-5247");
        Assert(current.Version == "9.9.9.99", "Current UU patch profile version mismatch.");
        Assert(current.Targets.Count == 7, "Current UU patch profile target count mismatch.");
        Assert(
            current.Targets.All(target => target.Signature is not null),
            "Current UU patch profile must provide a dynamic function signature for every target.");
        Assert(
            current.Targets.All(target =>
                target.OriginalBytes.Length == target.PatchedBytes.Length
                && target.OriginalBytes.Length > 0),
            "UU patch profile contains invalid target bytes.");

        var installedDll = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Netease",
            "UU",
            "5247",
            "local_proxy.dll");
        if (File.Exists(installedDll))
        {
            Assert(
                UuPatchLocator.TryResolve(
                    profiles,
                    installedDll,
                    "UNKNOWN-UU-HASH",
                    out var resolvedProfile,
                    out var resolvedTargets,
                    out var resolutionError),
                $"UU dynamic signature resolution failed: {resolutionError}");
            Assert(
                resolvedProfile?.Key == "uu-5247" && resolvedTargets.Count == current.Targets.Count,
                "UU dynamic signature resolution selected the wrong profile or target count.");
        }
    }

    private static void TestWinDivertUdpErrorBuilder()
    {
        var payload = "udp-error"u8.ToArray();
        var remoteV4 = IPAddress.Parse("198.51.100.20");
        var clientV4 = IPAddress.Parse("192.0.2.10");
        var packetV4 = WinDivertPacketBuilder.BuildUdpError(
            remoteV4,
            443,
            clientV4,
            50000,
            payload,
            SocketError.ConnectionRefused);
        Assert(packetV4[9] == 1, "IPv4 UDP error packet is not ICMP.");
        Assert(packetV4[20] == 3 && packetV4[21] == 3, "IPv4 UDP error type/code mismatch.");
        Assert(ComputeChecksum(packetV4.AsSpan(0, 20)) == 0, "IPv4 UDP error header checksum is invalid.");
        Assert(ComputeChecksum(packetV4.AsSpan(20)) == 0, "IPv4 UDP error ICMP checksum is invalid.");

        var remoteV6 = IPAddress.Parse("2001:db8::20");
        var clientV6 = IPAddress.Parse("2001:db8::10");
        var packetV6 = WinDivertPacketBuilder.BuildUdpError(
            remoteV6,
            443,
            clientV6,
            50000,
            payload,
            SocketError.ConnectionRefused);
        Assert(packetV6[6] == 58, "IPv6 UDP error packet is not ICMPv6.");
        Assert(packetV6[40] == 1 && packetV6[41] == 4, "IPv6 UDP error type/code mismatch.");
        Assert(
            ComputeTransportChecksum(
                remoteV6,
                clientV6,
                protocol: 58,
                packetV6.AsSpan(40)) == 0,
            "IPv6 UDP error ICMP checksum is invalid.");
    }

    private static void TestWinDivertUdpFragmentation()
    {
        var payload = new byte[4000];
        Random.Shared.NextBytes(payload);
        var fragmentsV4 = WinDivertPacketBuilder.BuildUdpFragments(
            IPAddress.Parse("198.51.100.20"),
            443,
            IPAddress.Parse("192.0.2.10"),
            50000,
            payload,
            mtu: 1500);
        Assert(fragmentsV4.Count > 1, "IPv4 UDP response was not fragmented.");
        Assert(fragmentsV4.All(packet => packet.Length <= 1500), "IPv4 UDP fragment exceeds MTU.");
        Assert(
            (BinaryPrimitives.ReadUInt16BigEndian(fragmentsV4[0].AsSpan(6, 2)) & 0x2000) != 0,
            "IPv4 first UDP fragment does not set MF.");
        Assert(
            (BinaryPrimitives.ReadUInt16BigEndian(fragmentsV4[^1].AsSpan(6, 2)) & 0x2000) == 0,
            "IPv4 last UDP fragment unexpectedly sets MF.");

        var fragmentsV6 = WinDivertPacketBuilder.BuildUdpFragments(
            IPAddress.Parse("2001:db8::20"),
            443,
            IPAddress.Parse("2001:db8::10"),
            50000,
            payload,
            mtu: 1500);
        Assert(fragmentsV6.Count > 1, "IPv6 UDP response was not fragmented.");
        Assert(fragmentsV6.All(packet => packet.Length <= 1500), "IPv6 UDP fragment exceeds MTU.");
        Assert(fragmentsV6.All(packet => packet[6] == 44), "IPv6 UDP fragment header is missing.");
        Assert(
            (BinaryPrimitives.ReadUInt16BigEndian(fragmentsV6[^1].AsSpan(42, 2)) & 1) == 0,
            "IPv6 last UDP fragment unexpectedly sets more-fragments.");
    }

    private static void TestUuPatchPersistence()
    {
        var directory = Directory.CreateTempSubdirectory("proxifyre-uu-config-");
        try
        {
            var configPath = Path.Combine(directory.FullName, "app-config.json");
            AppConfiguration.SaveApps(
                configPath,
                ["steamwebhelper.exe"],
                "steamwebhelper.exe",
                enableUuWhitelistPatch: true);
            Assert(
                AppConfiguration.Load(configPath).EnableUuWhitelistPatch,
                "UU whitelist patch setting did not persist in app-config.json.");

            AppConfiguration.SaveApps(
                configPath,
                ["steamwebhelper.exe"],
                "steamwebhelper.exe",
                enableUuWhitelistPatch: false);
            Assert(
                !AppConfiguration.Load(configPath).EnableUuWhitelistPatch,
                "UU whitelist patch setting could not be disabled.");
            Assert(
                !new ConfigurationStore(configPath).GetUuWhitelistPatchEnabled(),
                "Disabled UU whitelist patch setting incorrectly reported as enabled.");
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static void TestDisabledApplicationPersistence()
    {
        var directory = Directory.CreateTempSubdirectory("proxifyre-disabled-apps-");
        try
        {
            var configPath = Path.Combine(directory.FullName, "app-config.json");
            AppConfiguration.SaveApps(
                configPath,
                ["enabled.exe"],
                "steamwebhelper.exe",
                disabledApps: ["disabled.exe"]);

            var loaded = AppConfiguration.Load(configPath);
            Assert(loaded.Apps.SequenceEqual(["enabled.exe"]), "Enabled application list did not round-trip.");
            Assert(
                loaded.DisabledApps.SequenceEqual(["disabled.exe"]),
                "Disabled application list did not round-trip.");
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static void TestModuleMessageProtocol()
    {
        var payload = ModuleMessageProtocol.BuildCommand(
            "RUN",
            configPath: @"C:\config.json",
            logPath: @"C:\core.log",
            replyHwnd: 123,
            detailed: true,
            telemetryPipeName: "telemetry",
            nativeDirectory: @"C:\native",
            networkHandle: 456,
            flowHandle: 789,
            sessionToken: "A1B2C3");
        Assert(
            ModuleMessageProtocol.TryParse(payload, out var values),
            "Module command payload did not parse.");
        Assert(values["command"] == "RUN", "Module command name mismatch.");
        Assert(values["sessionToken"] == "A1B2C3", "Module session token mismatch.");
        Assert(ModuleMessageProtocol.GetHandle(values, "networkHandle") == new nint(456), "Module network handle mismatch.");
        Assert(ModuleMessageProtocol.GetHandle(values, "flowHandle") == new nint(789), "Module flow handle mismatch.");
        Assert(values["nativeDirectory"] == @"C:\native", "Module native directory mismatch.");
    }

    private static void TestNetworkInterfaceIndexResolution()
    {
        var resolved = 0;
        var resolvedByDeviceId = 0;
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!NetworkInterfaceIndexResolver.TryGetIndex(networkInterface, out var index))
            {
                continue;
            }

            Assert(index > 0, $"Network interface '{networkInterface.Name}' returned an invalid index.");
            resolved++;

            foreach (var unicast in networkInterface.GetIPProperties().UnicastAddresses)
            {
                if (unicast.Address.Equals(IPAddress.Any)
                    || unicast.Address.Equals(IPAddress.IPv6Any)
                    || unicast.Address.IsIPv6LinkLocal
                    || IsAutomaticPrivateAddress(unicast.Address))
                {
                    continue;
                }

                Assert(
                    NetworkInterfaceIndexResolver.FindInterfaceIndexForLocalAddress(unicast.Address) == index,
                    $"Local address '{unicast.Address}' for '{networkInterface.Name}' resolved to the wrong interface.");
            }

            var adapterDeviceName = $@"\DEVICE\{networkInterface.Id}";
            var resolvedIndex = NetworkInterfaceIndexResolver.FindAdapterIndex(adapterDeviceName, Array.Empty<byte>());
            if (resolvedIndex <= 0)
            {
                continue;
            }

            Assert(
                resolvedIndex == index,
                $"Network adapter device ID for '{networkInterface.Name}' resolved to the wrong interface index.");
            resolvedByDeviceId++;
        }

        Assert(resolved > 0, "No Windows network interface index could be resolved.");
        Assert(resolvedByDeviceId > 0, "No network adapter device ID could be resolved through NetworkInterface.Id.");
    }

    private static void TestRuntimeModuleCopy()
    {
        var root = Directory.CreateTempSubdirectory("proxifyre-runtime-copy-");
        try
        {
            var sourceDirectory = Path.Combine(root.FullName, "source");
            var runtimeDirectory = Path.Combine(root.FullName, "runtime");
            Directory.CreateDirectory(sourceDirectory);

            var sourceDll = Path.Combine(sourceDirectory, "ProxiFyre.Module.dll");
            var firstContent = Enumerable.Range(0, 4096).Select(value => (byte)value).ToArray();
            File.WriteAllBytes(sourceDll, firstContent);

            var firstCopy = AotModuleController.PrepareRuntimeCopy(
                sourceDll,
                runtimeDirectory,
                "ProxiFyre.Module.dll");
            var firstHash = Convert.ToHexString(SHA256.HashData(firstContent));
            Assert(
                Path.GetFileName(firstCopy).Equals(
                    $"ProxiFyre.Module.{firstHash}.dll",
                    StringComparison.OrdinalIgnoreCase),
                "Runtime module copy does not use its SHA-256 content hash.");
            Assert(File.ReadAllBytes(firstCopy).SequenceEqual(firstContent), "Runtime module copy content mismatch.");

            var repeatedCopy = AotModuleController.PrepareRuntimeCopy(
                sourceDll,
                runtimeDirectory,
                "ProxiFyre.Module.dll");
            Assert(
                repeatedCopy.Equals(firstCopy, StringComparison.OrdinalIgnoreCase),
                "Identical runtime module content produced a different copy.");
            Assert(
                Directory.EnumerateFiles(runtimeDirectory, "ProxiFyre.Module*.dll").Count() == 1,
                "Identical runtime module content left duplicate DLL copies.");

            var secondContent = firstContent.ToArray();
            secondContent[0] ^= 0xFF;
            File.WriteAllBytes(sourceDll, secondContent);

            var secondCopy = AotModuleController.PrepareRuntimeCopy(
                sourceDll,
                runtimeDirectory,
                "ProxiFyre.Module.dll");
            Assert(!secondCopy.Equals(firstCopy, StringComparison.OrdinalIgnoreCase), "Changed runtime module content reused the old copy.");
            Assert(File.ReadAllBytes(secondCopy).SequenceEqual(secondContent), "Updated runtime module copy content mismatch.");
            Assert(
                Directory.EnumerateFiles(runtimeDirectory, "ProxiFyre.Module*.dll").Count() == 1,
                "Stale runtime module copy was not cleaned up.");
        }
        finally
        {
            Directory.Delete(root.FullName, recursive: true);
        }
    }

    private static byte[] BuildIpv4Packet(
        IPAddress source,
        IPAddress destination,
        byte protocol,
        ushort sourcePort,
        ushort destinationPort,
        byte[] payload,
        int? declaredTransportLength = null,
        byte[]? tcpOptions = null,
        byte tcpFlags = 0,
        ushort urgentPointer = 0)
    {
        var transportOptions = tcpOptions ?? [];
        var transportHeaderLength = protocol == PacketView.ProtocolTcp ? 20 + transportOptions.Length : 8;
        var declaredLength = declaredTransportLength ?? transportHeaderLength + payload.Length;
        var transportLength = declaredTransportLength is null
            ? declaredLength
            : declaredLength + 4;
        var packet = new byte[14 + 20 + transportLength];
        packet.AsSpan(0, 6).Fill(0x10);
        packet.AsSpan(6, 6).Fill(0x20);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(12, 2), PacketView.EtherTypeIpv4);
        var ip = packet.AsSpan(14, 20);
        ip[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)(20 + transportLength));
        ip[8] = 64;
        ip[9] = protocol;
        source.GetAddressBytes().CopyTo(ip.Slice(12, 4));
        destination.GetAddressBytes().CopyTo(ip.Slice(16, 4));
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(10, 2), ComputeChecksum(ip));
        var transport = packet.AsSpan(34);
        BinaryPrimitives.WriteUInt16BigEndian(transport.Slice(0, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(transport.Slice(2, 2), destinationPort);
        if (protocol == PacketView.ProtocolUdp)
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                transport.Slice(4, 2),
                (ushort)declaredLength);
        }
        else
        {
            transport[12] = (byte)((transportHeaderLength / 4) << 4);
            transport[13] = tcpFlags;
            BinaryPrimitives.WriteUInt16BigEndian(transport.Slice(14, 2), 65535);
            BinaryPrimitives.WriteUInt16BigEndian(transport.Slice(18, 2), urgentPointer);
            transportOptions.CopyTo(transport.Slice(20));
        }

        payload.CopyTo(transport.Slice(transportHeaderLength));
        return packet;
    }

    private static byte[] BuildIpv6Packet(
        IPAddress source,
        IPAddress destination,
        byte protocol,
        ushort sourcePort,
        ushort destinationPort,
        byte[] payload)
    {
        var packet = new byte[14 + 40 + 8 + payload.Length];
        packet.AsSpan(0, 6).Fill(0x30);
        packet.AsSpan(6, 6).Fill(0x40);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(12, 2), PacketView.EtherTypeIpv6);
        var ip = packet.AsSpan(14, 40);
        ip[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), (ushort)(8 + payload.Length));
        ip[6] = protocol;
        ip[7] = 64;
        source.GetAddressBytes().CopyTo(ip.Slice(8, 16));
        destination.GetAddressBytes().CopyTo(ip.Slice(24, 16));
        var udp = packet.AsSpan(54);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(0, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(4, 2), (ushort)(8 + payload.Length));
        payload.CopyTo(udp.Slice(8));
        return packet;
    }

    private static ushort ComputeChecksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        for (var i = 0; i + 1 < data.Length; i += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
        }

        if ((data.Length & 1) != 0)
        {
            sum += (uint)(data[^1] << 8);
        }

        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }

    private static ushort ComputeTransportChecksum(
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        byte protocol,
        ReadOnlySpan<byte> transport)
    {
        var pseudoHeader = new byte[
            sourceAddress.GetAddressBytes().Length
            + destinationAddress.GetAddressBytes().Length
            + 4
            + transport.Length];
        var offset = 0;
        sourceAddress.GetAddressBytes().CopyTo(pseudoHeader, offset);
        offset += sourceAddress.GetAddressBytes().Length;
        destinationAddress.GetAddressBytes().CopyTo(pseudoHeader, offset);
        offset += destinationAddress.GetAddressBytes().Length;
        pseudoHeader[offset + 1] = protocol;
        BinaryPrimitives.WriteUInt16BigEndian(
            pseudoHeader.AsSpan(offset + 2, 2),
            (ushort)transport.Length);
        transport.CopyTo(pseudoHeader.AsSpan(offset + 4));
        return ComputeChecksum(pseudoHeader);
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static bool IsAutomaticPrivateAddress(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 169 && bytes[1] == 254;
    }

    private static void AssertThrows<TException>(Action action, string message)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }
}
