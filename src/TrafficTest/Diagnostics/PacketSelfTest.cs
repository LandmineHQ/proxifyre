using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
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
            TestIpv4UdpFragmentPayloadCopy();
            TestVlanParsing();
            TestTcpOptionsAndUrgentPointer();
            TestIpv4FragmentReassembly();
            TestIpv6FragmentReassembly();
            TestOutboundPassFlowRegistry();
            TestTrafficCounterBreakdown();
            TestWfpProtocolLayout();
            TestUuPatchProfileCatalog();
            TestUuPatchPersistence();
            TestDisabledApplicationPersistence();
            TestNetworkInterfaceIndexResolution();
            TestRuntimeModuleCopy();
            Console.WriteLine("PASS: packet parsing, multicast detection, VLAN, TCP fields, fragment reassembly, TCP/UDP traffic counters, UU patch profiles/config, interface indexes, and runtime module copies.");
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

    private static void TestIpv4UdpFragmentPayloadCopy()
    {
        var frame = new byte[PacketView.EthernetHeaderLength + 20 + 16];
        var payload = "fragment-payload"u8;
        PacketInjector.CopyIpv4UdpFragmentPayload(
            frame,
            PacketView.EthernetHeaderLength,
            payload);
        Assert(
            frame.AsSpan(PacketView.EthernetHeaderLength + 20, payload.Length).SequenceEqual(payload),
            "IPv4 UDP fragment payload was copied to the wrong offset.");
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

    private static void TestIpv4FragmentReassembly()
    {
        var payload = Enumerable.Range(0, 4000).Select(value => (byte)value).ToArray();
        var full = BuildIpv4Packet(
            IPAddress.Parse("192.0.2.13"),
            IPAddress.Parse("198.51.100.23"),
            PacketView.ProtocolUdp,
            4000,
            5000,
            payload);
        var reassembler = new IpFragmentReassembler();
        ReassembledIpPacket? result = null;

        foreach (var fragment in FragmentIpv4(full, 1400))
        {
            var status = reassembler.Add(
                fragment,
                fragment.Length,
                IntPtr.Zero,
                1,
                0,
                out var candidate,
                out _);
            if (status == FragmentAddStatus.Complete)
            {
                result = candidate;
            }
        }

        Assert(result is not null, "IPv4 fragments were not reassembled.");
        Assert(PacketView.TryParse(result!.Frame, result.Length, out var view), "Reassembled IPv4 packet did not parse.");
        Assert(view.UdpPayload.SequenceEqual(payload), "Reassembled IPv4 UDP payload mismatch.");

        var invalidFragment = BuildIpv4Packet(
            IPAddress.Parse("192.0.2.14"),
            IPAddress.Parse("198.51.100.24"),
            PacketView.ProtocolUdp,
            4100,
            5100,
            [0x01]);
        BinaryPrimitives.WriteUInt16BigEndian(invalidFragment.AsSpan(20, 2), 0x2000);
        var invalidStatus = reassembler.Add(
            invalidFragment,
            invalidFragment.Length,
            IntPtr.Zero,
            1,
            0,
            out _,
            out var fragmentsToPass);
        Assert(invalidStatus == FragmentAddStatus.Invalid, "Invalid IPv4 fragment was not rejected.");
        Assert(
            fragmentsToPass is { Count: 1 }
                && fragmentsToPass[0].Frame.AsSpan(0, fragmentsToPass[0].Length).SequenceEqual(invalidFragment),
            "Invalid IPv4 fragment was not returned for transparent replay.");
    }

    private static void TestIpv6FragmentReassembly()
    {
        var payload = Enumerable.Range(0, 3000).Select(value => (byte)(value + 17)).ToArray();
        var full = BuildIpv6Packet(
            IPAddress.Parse("2001:db8::13"),
            IPAddress.Parse("2001:db8::23"),
            PacketView.ProtocolUdp,
            6000,
            7000,
            payload);
        var reassembler = new IpFragmentReassembler();
        ReassembledIpPacket? result = null;

        foreach (var fragment in FragmentIpv6(full, 1200))
        {
            var status = reassembler.Add(
                fragment,
                fragment.Length,
                IntPtr.Zero,
                1,
                0,
                out var candidate,
                out _);
            if (status == FragmentAddStatus.Complete)
            {
                result = candidate;
            }
        }

        Assert(result is not null, "IPv6 fragments were not reassembled.");
        Assert(PacketView.TryParse(result!.Frame, result.Length, out var view), "Reassembled IPv6 packet did not parse.");
        Assert(view.UdpPayload.SequenceEqual(payload), "Reassembled IPv6 UDP payload mismatch.");
    }

    private static void TestOutboundPassFlowRegistry()
    {
        var registry = new OutboundPassFlowRegistry(maxFlows: 2, ttl: TimeSpan.FromSeconds(10));
        var first = new RelayOutboundFlow(
            IntPtr.Zero,
            PacketView.ProtocolUdp,
            IPAddress.Loopback,
            IPAddress.Parse("198.51.100.30"),
            1000,
            2000);
        var second = new RelayOutboundFlow(
            IntPtr.Zero,
            PacketView.ProtocolUdp,
            IPAddress.Loopback,
            IPAddress.Parse("198.51.100.31"),
            1001,
            2001);
        var third = new RelayOutboundFlow(
            IntPtr.Zero,
            PacketView.ProtocolTcp,
            IPAddress.Loopback,
            IPAddress.Parse("198.51.100.32"),
            1002,
            2002);

        var now = DateTimeOffset.UnixEpoch;
        registry.Register(first, now);
        registry.Register(second, now.AddSeconds(1));
        registry.Register(third, now.AddSeconds(2));
        registry.Register(second, now.AddSeconds(6));
        Assert(registry.Count == 2, "Outbound pass flow registry exceeded its capacity.");
        Assert(
            registry.Snapshot().All(flow => !flow.Equals(first)),
            "Outbound pass flow registry did not evict the oldest flow.");
        Assert(
            registry.RemoveExpired(now.AddSeconds(13)),
            "Outbound pass flow registry did not expire stale flows.");
        Assert(registry.Count == 1, "Outbound pass flow registry removed a refreshed flow.");
        Assert(
            registry.Snapshot().Single().Equals(second),
            "Outbound pass flow registry retained the wrong flow after expiry.");
        Assert(
            registry.RemoveExpired(now.AddSeconds(17)),
            "Outbound pass flow registry did not expire the refreshed flow.");
        Assert(registry.Count == 0, "Outbound pass flow registry retained expired flows.");
    }

    private static void TestWfpProtocolLayout()
    {
        Assert(
            Marshal.SizeOf<WfpFlowEvent>() == 72,
            "WFP flow event layout does not match the native protocol.");
        Assert(
            Marshal.SizeOf<WfpVerdict>() == 16,
            "WFP verdict layout does not match the native protocol.");
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

            var winpkFilterName = $@"\DEVICE\{networkInterface.Id}";
            var resolvedIndex = NetworkInterfaceIndexResolver.FindAdapterIndex(winpkFilterName, Array.Empty<byte>());
            if (resolvedIndex <= 0)
            {
                continue;
            }

            Assert(
                resolvedIndex == index,
                $"WinpkFilter device ID for '{networkInterface.Name}' resolved to the wrong interface index.");
            resolvedByDeviceId++;
        }

        Assert(resolved > 0, "No Windows network interface index could be resolved.");
        Assert(resolvedByDeviceId > 0, "No WinpkFilter device ID could be resolved through NetworkInterface.Id.");
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

    private static IEnumerable<byte[]> FragmentIpv4(byte[] packet, int maxPayload)
    {
        const int ipOffset = 14;
        const int ipHeaderLength = 20;
        var ipPayload = packet.AsSpan(ipOffset + ipHeaderLength).ToArray();
        var identification = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(ipOffset + 4, 2));
        for (var offset = 0; offset < ipPayload.Length; offset += maxPayload)
        {
            var length = Math.Min(maxPayload, ipPayload.Length - offset);
            var more = offset + length < ipPayload.Length;
            var fragment = new byte[ipOffset + ipHeaderLength + length];
            packet.AsSpan(0, ipOffset).CopyTo(fragment);
            var ip = fragment.AsSpan(ipOffset, ipHeaderLength);
            ip[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)(ipHeaderLength + length));
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), identification);
            BinaryPrimitives.WriteUInt16BigEndian(
                ip.Slice(6, 2),
                (ushort)((offset / 8) | (more ? 0x2000 : 0)));
            ip[8] = 64;
            ip[9] = packet[ipOffset + 9];
            packet.AsSpan(ipOffset + 12, 8).CopyTo(ip.Slice(12, 8));
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(10, 2), ComputeChecksum(ip));
            ipPayload.AsSpan(offset, length).CopyTo(fragment.AsSpan(ipOffset + ipHeaderLength));
            yield return fragment;
        }
    }

    private static IEnumerable<byte[]> FragmentIpv6(byte[] packet, int maxPayload)
    {
        const int ipOffset = 14;
        const int ipHeaderLength = 40;
        var ipPayload = packet.AsSpan(ipOffset + ipHeaderLength).ToArray();
        var identification = 0x11223344u;
        for (var offset = 0; offset < ipPayload.Length; offset += maxPayload)
        {
            var length = Math.Min(maxPayload, ipPayload.Length - offset);
            var more = offset + length < ipPayload.Length;
            var fragment = new byte[ipOffset + ipHeaderLength + 8 + length];
            packet.AsSpan(0, ipOffset).CopyTo(fragment);
            var ip = fragment.AsSpan(ipOffset, ipHeaderLength);
            ip[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), (ushort)(8 + length));
            ip[6] = 44;
            ip[7] = 64;
            packet.AsSpan(ipOffset + 8, 32).CopyTo(ip.Slice(8, 32));
            var fragmentHeader = fragment.AsSpan(ipOffset + 40, 8);
            fragmentHeader[0] = packet[ipOffset + 6];
            BinaryPrimitives.WriteUInt16BigEndian(
                fragmentHeader.Slice(2, 2),
                (ushort)(((offset / 8) << 3) | (more ? 1 : 0)));
            BinaryPrimitives.WriteUInt32BigEndian(fragmentHeader.Slice(4, 4), identification);
            ipPayload.AsSpan(offset, length).CopyTo(fragment.AsSpan(ipOffset + 48));
            yield return fragment;
        }
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

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
