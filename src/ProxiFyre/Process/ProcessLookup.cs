using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace ProxiFyre;

internal sealed class ProcessLookup
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const int ErrorInsufficientBuffer = 122;
    private const int NoError = 0;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private static readonly TimeSpan ForcedRefreshInterval = TimeSpan.FromMilliseconds(100);

    private readonly TimeSpan _refreshInterval = TimeSpan.FromMilliseconds(250);
    private readonly TimeSpan _processCacheTtl = TimeSpan.FromSeconds(1);
    private readonly TimeSpan _processIdentityCacheTtl = TimeSpan.FromMilliseconds(250);
    private readonly ConcurrentDictionary<int, CachedProcessInfo> _processCache = new();
    private readonly ConcurrentDictionary<int, ProcessIdentityCheck> _processIdentityChecks = new();
    private readonly ConcurrentDictionary<string, long> _warningTimes = new();
    private readonly Action<string> _log;
    private readonly Action<string> _warningLog;
    private readonly TimeProvider _timeProvider;
    private readonly bool _logRefreshes;
    private readonly object _sync = new();
    private Dictionary<TcpSessionKey, int> _tcpOwners = new();
    private Dictionary<UdpEndpointKey, int> _tcpLocalOwners = new();
    private Dictionary<ushort, int> _tcpPortOwners = new();
    private Dictionary<UdpEndpointKey, int> _tcpListeners = new();
    private Dictionary<UdpEndpointKey, int> _udpOwners = new();
    private DateTimeOffset _lastTcpRefresh = DateTimeOffset.MinValue;
    private DateTimeOffset _lastUdpRefresh = DateTimeOffset.MinValue;
    private DateTimeOffset _nextTcpForcedRefresh = DateTimeOffset.MinValue;
    private DateTimeOffset _nextUdpForcedRefresh = DateTimeOffset.MinValue;

    public ProcessLookup(
        Action<string>? log = null,
        TimeProvider? timeProvider = null,
        bool logRefreshes = false,
        Action<string>? warningLog = null)
    {
        _log = log ?? (_ => { });
        _warningLog = warningLog ?? _log;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logRefreshes = logRefreshes;
    }

    public ProcessInfo? LookupTcpOwner(TcpSessionKey session, bool forceRefresh = false)
    {
        return TryGetTcpOwnerPid(session, forceRefresh, out var pid)
            ? GetProcessInfo(pid)
            : null;
    }

    public bool TryGetTcpOwnerPid(
        TcpSessionKey session,
        bool forceRefresh,
        out int pid)
    {
        if (forceRefresh)
        {
            RefreshTcp(force: true);
        }
        else
        {
            EnsureTcpFresh();
        }

        if (_tcpOwners.TryGetValue(session, out var ownerPid) && ownerPid > 0)
        {
            pid = ownerPid;
            return true;
        }

        if (TryLookupTcpLocalPid(session.LocalAddress, session.LocalPort, out pid))
        {
            return true;
        }

        RefreshTcp(force: true);

        if (_tcpOwners.TryGetValue(session, out ownerPid) && ownerPid > 0)
        {
            pid = ownerPid;
            return true;
        }

        return TryLookupTcpLocalPid(session.LocalAddress, session.LocalPort, out pid);
    }

    public ProcessInfo? LookupUdpOwner(UdpEndpointKey endpoint, bool forceRefresh = false)
    {
        return TryGetUdpOwnerPid(endpoint, forceRefresh, out var pid)
            ? GetProcessInfo(pid)
            : null;
    }

    public bool TryGetUdpOwnerPid(
        UdpEndpointKey endpoint,
        bool forceRefresh,
        out int pid)
    {
        if (forceRefresh)
        {
            RefreshUdp(force: true);
        }
        else
        {
            EnsureUdpFresh();
        }

        if (TryLookupUdpPid(endpoint, out var ownerPid) && ownerPid > 0)
        {
            pid = ownerPid;
            return true;
        }

        RefreshUdp(force: true);

        return TryLookupUdpPid(endpoint, out pid);
    }

    private bool TryLookupUdpPid(UdpEndpointKey endpoint, out int pid)
    {
        if (_udpOwners.TryGetValue(endpoint, out pid))
        {
            return pid > 0;
        }

        var wildcard = endpoint.LocalAddress.AddressFamily == AddressFamily.InterNetwork
            ? IPAddress.Any
            : IPAddress.IPv6Any;

        if (_udpOwners.TryGetValue(new UdpEndpointKey(wildcard, endpoint.LocalPort), out pid))
        {
            return pid > 0;
        }

        pid = 0;
        return false;
    }

    private bool TryLookupTcpLocalPid(IPAddress localAddress, ushort localPort, out int pid)
    {
        var endpoint = new UdpEndpointKey(localAddress, localPort);
        if (_tcpLocalOwners.TryGetValue(endpoint, out pid))
        {
            return pid > 0;
        }

        if (_tcpListeners.TryGetValue(endpoint, out pid))
        {
            return pid > 0;
        }

        var wildcard = localAddress.AddressFamily == AddressFamily.InterNetwork
            ? IPAddress.Any
            : IPAddress.IPv6Any;

        if (_tcpLocalOwners.TryGetValue(new UdpEndpointKey(wildcard, localPort), out pid))
        {
            return pid > 0;
        }

        if (_tcpListeners.TryGetValue(new UdpEndpointKey(wildcard, localPort), out pid))
        {
            return pid > 0;
        }

        if (_tcpPortOwners.TryGetValue(localPort, out pid))
        {
            return pid > 0;
        }

        pid = 0;
        return false;
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

    private void RefreshTcp(bool force = false)
    {
        lock (_sync)
        {
            var now = _timeProvider.GetUtcNow();
            if (force && now < _nextTcpForcedRefresh)
            {
                return;
            }

            if (!force && now - _lastTcpRefresh <= _refreshInterval)
            {
                return;
            }

            if (force)
            {
                _nextTcpForcedRefresh = now + ForcedRefreshInterval;
            }

            var owners = new Dictionary<TcpSessionKey, int>();
            var localOwners = new Dictionary<UdpEndpointKey, int>();
            var portOwners = new Dictionary<ushort, int>();
            var listeners = new Dictionary<UdpEndpointKey, int>();
            AddTcp4(owners, localOwners, portOwners, listeners);
            AddTcp6(owners, localOwners, portOwners, listeners);
            _tcpOwners = owners;
            _tcpLocalOwners = localOwners;
            _tcpPortOwners = portOwners;
            _tcpListeners = listeners;
            _lastTcpRefresh = now;
            if (_logRefreshes)
            {
                _log($"Process lookup TCP table refreshed: sessions={owners.Count}, listeners={listeners.Count}");
            }
        }
    }

    private void RefreshUdp(bool force = false)
    {
        lock (_sync)
        {
            var now = _timeProvider.GetUtcNow();
            if (force && now < _nextUdpForcedRefresh)
            {
                return;
            }

            if (!force && now - _lastUdpRefresh <= _refreshInterval)
            {
                return;
            }

            if (force)
            {
                _nextUdpForcedRefresh = now + ForcedRefreshInterval;
            }

            var owners = new Dictionary<UdpEndpointKey, int>();
            AddUdp4(owners);
            AddUdp6(owners);
            _udpOwners = owners;
            _lastUdpRefresh = now;
            if (_logRefreshes)
            {
                _log($"Process lookup UDP table refreshed: endpoints={owners.Count}");
            }
        }
    }

    private void AddTcp4(
        Dictionary<TcpSessionKey, int> owners,
        Dictionary<UdpEndpointKey, int> localOwners,
        Dictionary<ushort, int> portOwners,
        Dictionary<UdpEndpointKey, int> listeners)
    {
        QueryTable(
            "TCP IPv4 owner table",
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
                    AddTcpLocalOwner(localOwners, portOwners, localAddress, localPort, row.OwningPid);
                    if (remotePort == 0)
                    {
                        AddOwner(
                            listeners,
                            new UdpEndpointKey(localAddress, localPort),
                            row.OwningPid);
                        continue;
                    }

                    owners[new TcpSessionKey(localAddress, FromIpv4RowAddress(row.RemoteAddr), localPort, remotePort)] = row.OwningPid;
                }
            });
    }

    private void AddTcp6(
        Dictionary<TcpSessionKey, int> owners,
        Dictionary<UdpEndpointKey, int> localOwners,
        Dictionary<ushort, int> portOwners,
        Dictionary<UdpEndpointKey, int> listeners)
    {
        QueryTable(
            "TCP IPv6 owner table",
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
                    AddTcpLocalOwner(localOwners, portOwners, localAddress, localPort, row.OwningPid);
                    if (remotePort == 0)
                    {
                        AddOwner(
                            listeners,
                            new UdpEndpointKey(localAddress, localPort),
                            row.OwningPid);
                        continue;
                    }

                    owners[new TcpSessionKey(localAddress, new IPAddress(row.RemoteAddr, row.RemoteScopeId), localPort, remotePort)] = row.OwningPid;
                }
            });
    }

    private static void AddTcpLocalOwner(
        Dictionary<UdpEndpointKey, int> localOwners,
        Dictionary<ushort, int> portOwners,
        IPAddress localAddress,
        ushort localPort,
        int pid)
    {
        AddOwner(
            localOwners,
            new UdpEndpointKey(localAddress, localPort),
            pid);

        if (portOwners.TryGetValue(localPort, out var existingPid))
        {
            if (existingPid != pid)
            {
                portOwners[localPort] = -1;
            }

            return;
        }

        portOwners[localPort] = pid;
    }

    private static void AddOwner(
        Dictionary<UdpEndpointKey, int> owners,
        UdpEndpointKey key,
        int pid)
    {
        if (owners.TryGetValue(key, out var existingPid) && existingPid != pid)
        {
            owners[key] = -1;
            return;
        }

        owners[key] = pid;
    }

    private void AddUdp4(Dictionary<UdpEndpointKey, int> owners)
    {
        QueryTable(
            "UDP IPv4 owner table",
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

                    AddOwner(
                        owners,
                        new UdpEndpointKey(FromIpv4RowAddress(row.LocalAddr), localPort),
                        row.OwningPid);
                }
            });
    }

    private void AddUdp6(Dictionary<UdpEndpointKey, int> owners)
    {
        QueryTable(
            "UDP IPv6 owner table",
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

                    AddOwner(
                        owners,
                        new UdpEndpointKey(new IPAddress(row.LocalAddr, row.LocalScopeId), localPort),
                        row.OwningPid);
                }
            });
    }

    private void QueryTable(
        string tableName,
        QueryTableDelegate query,
        Action<IntPtr> process)
    {
        var size = 0;
        var result = query(IntPtr.Zero, ref size);
        if (result != ErrorInsufficientBuffer && result != NoError)
        {
            LogWarningThrottled(
                $"process-table-size:{tableName}",
                $"Process lookup {tableName} size query failed with Win32 error {result}; retaining the previous table.");
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
            else
            {
                LogWarningThrottled(
                    $"process-table-query:{tableName}",
                    $"Process lookup {tableName} query failed with Win32 error {result}; retaining the previous table.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private void LogWarningThrottled(string category, string message)
    {
        var now = Environment.TickCount64;
        if (_warningTimes.TryGetValue(category, out var last) && now - last < 5000)
        {
            return;
        }

        _warningTimes[category] = now;
        _warningLog(message);
    }

    public ProcessInfo? GetProcessInfo(int pid, bool forceRefresh = false)
    {
        if (pid == Environment.ProcessId || pid is 0 or 4)
        {
            return null;
        }

        if (forceRefresh)
        {
            _processCache.TryRemove(pid, out _);
        }

        var now = _timeProvider.GetUtcNow();
        if (_processCache.TryGetValue(pid, out var cached))
        {
            if (now <= cached.ExpiresAt)
            {
                return cached.Process;
            }

            _processCache.TryRemove(pid, out _);
        }

        try
        {
            using var process = Process.GetProcessById(pid);
            var name = process.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? process.ProcessName
                : process.ProcessName + ".exe";

            var path = TryGetProcessImagePath(pid);
            if (path is null)
            {
                path = TryGetMainModulePath(process);
                if (path is not null)
                {
                    LogWarningThrottled(
                        "process-path-fallback",
                        $"Process image path lookup fell back to MainModule for pid={pid}.");
                }
            }

            path ??= name;
            long startTimeUtcTicks = 0;
            try
            {
                startTimeUtcTicks = process.StartTime.ToUniversalTime().Ticks;
            }
            catch
            {
            }

            var processInfo = new ProcessInfo(pid, name, path, startTimeUtcTicks);
            _processCache[pid] = new CachedProcessInfo(processInfo, now + _processCacheTtl);
            return processInfo;
        }
        catch
        {
            return null;
        }
    }

    public bool ValidateProcessIdentity(int pid, long expectedStartTimeUtcTicks)
    {
        if (expectedStartTimeUtcTicks == 0)
        {
            return GetProcessInfo(pid) is not null;
        }

        if (pid == Environment.ProcessId || pid is 0 or 4)
        {
            return false;
        }

        var now = _timeProvider.GetUtcNow();
        if (_processIdentityChecks.TryGetValue(pid, out var cached)
            && now <= cached.ExpiresAt)
        {
            return cached.StartTimeUtcTicks == expectedStartTimeUtcTicks;
        }

        try
        {
            using var process = Process.GetProcessById(pid);
            var startTimeUtcTicks = process.StartTime.ToUniversalTime().Ticks;
            _processIdentityChecks[pid] = new ProcessIdentityCheck(
                startTimeUtcTicks,
                now + _processIdentityCacheTtl);
            return startTimeUtcTicks == expectedStartTimeUtcTicks;
        }
        catch
        {
            _processIdentityChecks.TryRemove(pid, out _);
            return false;
        }
    }

    private static string? TryGetProcessImagePath(int pid)
    {
        var processHandle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (processHandle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var builder = new StringBuilder(32768);
            var capacity = builder.Capacity;
            if (!QueryFullProcessImageName(processHandle, 0, builder, ref capacity))
            {
                return null;
            }

            var path = builder.ToString();
            return string.IsNullOrWhiteSpace(path) ? null : path;
        }
        finally
        {
            CloseHandle(processHandle);
        }
    }

    private static string? TryGetMainModulePath(Process process)
    {
        try
        {
            var path = process.MainModule?.FileName;
            return string.IsNullOrWhiteSpace(path) ? null : path;
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId);

    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        IntPtr processHandle,
        int flags,
        StringBuilder exeName,
        ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

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

    private sealed record CachedProcessInfo(ProcessInfo Process, DateTimeOffset ExpiresAt);

    private sealed record ProcessIdentityCheck(
        long StartTimeUtcTicks,
        DateTimeOffset ExpiresAt);
}
