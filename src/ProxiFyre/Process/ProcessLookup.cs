using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ProxiFyre;

internal sealed class ProcessLookup
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const int ErrorInsufficientBuffer = 122;
    private const int NoError = 0;

    private readonly TimeSpan _refreshInterval = TimeSpan.FromMilliseconds(250);
    private readonly ConcurrentDictionary<int, ProcessInfo> _processCache = new();
    private readonly Action<string> _log;
    private readonly TimeProvider _timeProvider;
    private readonly object _sync = new();
    private Dictionary<TcpSessionKey, int> _tcpOwners = new();
    private Dictionary<UdpEndpointKey, int> _tcpListeners = new();
    private Dictionary<UdpEndpointKey, int> _udpOwners = new();
    private DateTimeOffset _lastTcpRefresh = DateTimeOffset.MinValue;
    private DateTimeOffset _lastUdpRefresh = DateTimeOffset.MinValue;

    public ProcessLookup(Action<string>? log = null, TimeProvider? timeProvider = null)
    {
        _log = log ?? (_ => { });
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public ProcessInfo? LookupTcpOwner(TcpSessionKey session)
    {
        EnsureTcpFresh();

        if (_tcpOwners.TryGetValue(session, out var pid))
        {
            return GetProcessInfo(pid);
        }

        if (TryLookupTcpLocalPid(session.LocalAddress, session.LocalPort, out pid))
        {
            return GetProcessInfo(pid);
        }

        RefreshTcp();

        if (_tcpOwners.TryGetValue(session, out pid))
        {
            return GetProcessInfo(pid);
        }

        return TryLookupTcpLocalPid(session.LocalAddress, session.LocalPort, out pid)
            ? GetProcessInfo(pid)
            : null;
    }

    public ProcessInfo? LookupUdpOwner(UdpEndpointKey endpoint)
    {
        EnsureUdpFresh();

        if (TryLookupUdpPid(endpoint, out var pid))
        {
            return GetProcessInfo(pid);
        }

        RefreshUdp();

        return TryLookupUdpPid(endpoint, out pid)
            ? GetProcessInfo(pid)
            : null;
    }

    private bool TryLookupUdpPid(UdpEndpointKey endpoint, out int pid)
    {
        if (_udpOwners.TryGetValue(endpoint, out pid))
        {
            return true;
        }

        var wildcard = endpoint.LocalAddress.AddressFamily == AddressFamily.InterNetwork
            ? IPAddress.Any
            : IPAddress.IPv6Any;

        return _udpOwners.TryGetValue(new UdpEndpointKey(wildcard, endpoint.LocalPort), out pid);
    }

    private bool TryLookupTcpLocalPid(IPAddress localAddress, ushort localPort, out int pid)
    {
        var endpoint = new UdpEndpointKey(localAddress, localPort);
        if (_tcpListeners.TryGetValue(endpoint, out pid))
        {
            return true;
        }

        var wildcard = localAddress.AddressFamily == AddressFamily.InterNetwork
            ? IPAddress.Any
            : IPAddress.IPv6Any;

        return _tcpListeners.TryGetValue(new UdpEndpointKey(wildcard, localPort), out pid);
    }

    private void EnsureTcpFresh()
    {
        if (_timeProvider.GetUtcNow() - _lastTcpRefresh > _refreshInterval)
        {
            RefreshTcp();
        }
    }

    private void EnsureUdpFresh()
    {
        if (_timeProvider.GetUtcNow() - _lastUdpRefresh > _refreshInterval)
        {
            RefreshUdp();
        }
    }

    private void RefreshTcp()
    {
        lock (_sync)
        {
            var now = _timeProvider.GetUtcNow();
            if (now - _lastTcpRefresh <= _refreshInterval)
            {
                return;
            }

            var owners = new Dictionary<TcpSessionKey, int>();
            var listeners = new Dictionary<UdpEndpointKey, int>();
            AddTcp4(owners, listeners);
            AddTcp6(owners, listeners);
            _tcpOwners = owners;
            _tcpListeners = listeners;
            _lastTcpRefresh = now;
            _log($"Process lookup TCP table refreshed: sessions={owners.Count}, listeners={listeners.Count}");
        }
    }

    private void RefreshUdp()
    {
        lock (_sync)
        {
            var now = _timeProvider.GetUtcNow();
            if (now - _lastUdpRefresh <= _refreshInterval)
            {
                return;
            }

            var owners = new Dictionary<UdpEndpointKey, int>();
            AddUdp4(owners);
            AddUdp6(owners);
            _udpOwners = owners;
            _lastUdpRefresh = now;
            _log($"Process lookup UDP table refreshed: endpoints={owners.Count}");
        }
    }

    private static void AddTcp4(Dictionary<TcpSessionKey, int> owners, Dictionary<UdpEndpointKey, int> listeners)
    {
        QueryTable(
            (IntPtr buffer, ref int size) => GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0),
            buffer =>
            {
                var rowCount = Marshal.ReadInt32(buffer);
                var rowPtr = IntPtr.Add(buffer, sizeof(uint));
                var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

                for (var i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    var localPort = FromNetworkOrderPort(row.LocalPort);
                    var remotePort = FromNetworkOrderPort(row.RemotePort);
                    if (localPort == 0)
                    {
                        continue;
                    }

                    var localAddress = FromIpv4RowAddress(row.LocalAddr);
                    if (remotePort == 0)
                    {
                        listeners[new UdpEndpointKey(localAddress, localPort)] = row.OwningPid;
                        continue;
                    }

                    owners[new TcpSessionKey(localAddress, FromIpv4RowAddress(row.RemoteAddr), localPort, remotePort)] = row.OwningPid;
                }
            });
    }

    private static void AddTcp6(Dictionary<TcpSessionKey, int> owners, Dictionary<UdpEndpointKey, int> listeners)
    {
        QueryTable(
            (IntPtr buffer, ref int size) => GetExtendedTcpTable(buffer, ref size, false, AfInet6, TcpTableOwnerPidAll, 0),
            buffer =>
            {
                var rowCount = Marshal.ReadInt32(buffer);
                var rowPtr = IntPtr.Add(buffer, sizeof(uint));
                var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();

                for (var i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    var localPort = FromNetworkOrderPort(row.LocalPort);
                    var remotePort = FromNetworkOrderPort(row.RemotePort);
                    if (localPort == 0)
                    {
                        continue;
                    }

                    var localAddress = new IPAddress(row.LocalAddr, row.LocalScopeId);
                    if (remotePort == 0)
                    {
                        listeners[new UdpEndpointKey(localAddress, localPort)] = row.OwningPid;
                        continue;
                    }

                    owners[new TcpSessionKey(localAddress, new IPAddress(row.RemoteAddr, row.RemoteScopeId), localPort, remotePort)] = row.OwningPid;
                }
            });
    }

    private static void AddUdp4(Dictionary<UdpEndpointKey, int> owners)
    {
        QueryTable(
            (IntPtr buffer, ref int size) => GetExtendedUdpTable(buffer, ref size, false, AfInet, UdpTableOwnerPid, 0),
            buffer =>
            {
                var rowCount = Marshal.ReadInt32(buffer);
                var rowPtr = IntPtr.Add(buffer, sizeof(uint));
                var rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();

                for (var i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    var localPort = FromNetworkOrderPort(row.LocalPort);
                    if (localPort == 0)
                    {
                        continue;
                    }

                    owners[new UdpEndpointKey(FromIpv4RowAddress(row.LocalAddr), localPort)] = row.OwningPid;
                }
            });
    }

    private static void AddUdp6(Dictionary<UdpEndpointKey, int> owners)
    {
        QueryTable(
            (IntPtr buffer, ref int size) => GetExtendedUdpTable(buffer, ref size, false, AfInet6, UdpTableOwnerPid, 0),
            buffer =>
            {
                var rowCount = Marshal.ReadInt32(buffer);
                var rowPtr = IntPtr.Add(buffer, sizeof(uint));
                var rowSize = Marshal.SizeOf<MibUdp6RowOwnerPid>();

                for (var i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MibUdp6RowOwnerPid>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    var localPort = FromNetworkOrderPort(row.LocalPort);
                    if (localPort == 0)
                    {
                        continue;
                    }

                    owners[new UdpEndpointKey(new IPAddress(row.LocalAddr, row.LocalScopeId), localPort)] = row.OwningPid;
                }
            });
    }

    private static void QueryTable(QueryTableDelegate query, Action<IntPtr> process)
    {
        var size = 0;
        var result = query(IntPtr.Zero, ref size);
        if (result != ErrorInsufficientBuffer && result != NoError)
        {
            return;
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            result = query(buffer, ref size);
            if (result == NoError)
            {
                process(buffer);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private ProcessInfo? GetProcessInfo(int pid)
    {
        if (pid == Environment.ProcessId || pid is 0 or 4)
        {
            return null;
        }

        if (_processCache.TryGetValue(pid, out var cached))
        {
            return cached;
        }

        try
        {
            using var process = Process.GetProcessById(pid);
            var name = process.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? process.ProcessName
                : process.ProcessName + ".exe";

            var path = string.Empty;
            try
            {
                path = process.MainModule?.FileName ?? string.Empty;
            }
            catch
            {
                path = name;
            }

            var processInfo = new ProcessInfo(pid, name, path);
            _processCache.TryAdd(pid, processInfo);
            return processInfo;
        }
        catch
        {
            return null;
        }
    }

    private static ushort FromNetworkOrderPort(uint port)
    {
        return (ushort)IPAddress.NetworkToHostOrder((short)(port & 0xFFFF));
    }

    private static IPAddress FromIpv4RowAddress(uint address)
    {
        return new IPAddress(BitConverter.GetBytes(address));
    }

    private delegate int QueryTableDelegate(IntPtr buffer, ref int size);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        [MarshalAs(UnmanagedType.Bool)] bool sort,
        int ipVersion,
        int tblClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int dwOutBufLen,
        [MarshalAs(UnmanagedType.Bool)] bool sort,
        int ipVersion,
        int tblClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public int OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public int OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public uint LocalPort;
        public int OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        public int OwningPid;
    }
}
