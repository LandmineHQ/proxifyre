using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace TrafficTest;

internal static class WindowsNetworkTable
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int ErrorInsufficientBuffer = 122;

    public static IReadOnlyList<WindowsTcpRow> GetTcpRows()
    {
        var rows = new List<WindowsTcpRow>();
        rows.AddRange(ReadTcp4Rows());
        rows.AddRange(ReadTcp6Rows());
        return rows;
    }

    public static IReadOnlyList<WindowsUdpRow> GetUdpRows()
    {
        var rows = new List<WindowsUdpRow>();
        rows.AddRange(ReadUdp4Rows());
        rows.AddRange(ReadUdp6Rows());
        return rows;
    }

    public static IReadOnlyList<WindowsTcpRow> GetTcpRowsForProcesses(IEnumerable<int> processIds)
    {
        var ids = processIds.ToHashSet();
        return GetTcpRows().Where(row => ids.Contains(row.ProcessId)).ToArray();
    }

    public static IReadOnlyList<WindowsUdpRow> GetUdpRowsForProcesses(IEnumerable<int> processIds)
    {
        var ids = processIds.ToHashSet();
        return GetUdpRows().Where(row => ids.Contains(row.ProcessId)).ToArray();
    }

    public static bool IsLoopbackOrAny(string address)
    {
        return address is "0.0.0.0" or "::" or "127.0.0.1" or "::1";
    }

    public static bool RemoteMatchesListener(WindowsTcpRow connection, WindowsTcpRow listener)
    {
        if (connection.RemotePort != listener.LocalPort)
        {
            return false;
        }

        return listener.LocalAddress is "0.0.0.0" or "::"
            || connection.RemoteAddress.Equals(listener.LocalAddress, StringComparison.OrdinalIgnoreCase)
            || (IsLoopback(connection.RemoteAddress) && IsLoopback(listener.LocalAddress));
    }

    private static IReadOnlyList<WindowsTcpRow> ReadTcp4Rows()
    {
        return QueryTable<MibTcpRowOwnerPid, WindowsTcpRow>(
            (IntPtr buffer, ref int size) => GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableClass.OwnerPidAll, 0),
            row =>
            {
                var localAddress = new IPAddress(BitConverter.GetBytes(row.LocalAddress)).ToString();
                var remoteAddress = new IPAddress(BitConverter.GetBytes(row.RemoteAddress)).ToString();
                return new WindowsTcpRow(
                    row.OwningProcessId,
                    "IPv4",
                    localAddress,
                    DecodePort(row.LocalPort),
                    remoteAddress,
                    DecodePort(row.RemotePort),
                    (TcpState)row.State);
            });
    }

    private static IReadOnlyList<WindowsTcpRow> ReadTcp6Rows()
    {
        return QueryTable<MibTcp6RowOwnerPid, WindowsTcpRow>(
            (IntPtr buffer, ref int size) => GetExtendedTcpTable(buffer, ref size, true, AfInet6, TcpTableClass.OwnerPidAll, 0),
            row =>
            {
                var localAddress = new IPAddress(row.LocalAddress, row.LocalScopeId).ToString();
                var remoteAddress = new IPAddress(row.RemoteAddress, row.RemoteScopeId).ToString();
                return new WindowsTcpRow(
                    row.OwningProcessId,
                    "IPv6",
                    localAddress,
                    DecodePort(row.LocalPort),
                    remoteAddress,
                    DecodePort(row.RemotePort),
                    (TcpState)row.State);
            });
    }

    private static IReadOnlyList<WindowsUdpRow> ReadUdp4Rows()
    {
        return QueryTable<MibUdpRowOwnerPid, WindowsUdpRow>(
            (IntPtr buffer, ref int size) => GetExtendedUdpTable(buffer, ref size, true, AfInet, UdpTableClass.OwnerPid, 0),
            row =>
            {
                var localAddress = new IPAddress(BitConverter.GetBytes(row.LocalAddress)).ToString();
                return new WindowsUdpRow(row.OwningProcessId, "IPv4", localAddress, DecodePort(row.LocalPort));
            });
    }

    private static IReadOnlyList<WindowsUdpRow> ReadUdp6Rows()
    {
        return QueryTable<MibUdp6RowOwnerPid, WindowsUdpRow>(
            (IntPtr buffer, ref int size) => GetExtendedUdpTable(buffer, ref size, true, AfInet6, UdpTableClass.OwnerPid, 0),
            row =>
            {
                var localAddress = new IPAddress(row.LocalAddress, row.LocalScopeId).ToString();
                return new WindowsUdpRow(row.OwningProcessId, "IPv6", localAddress, DecodePort(row.LocalPort));
            });
    }

    private static IReadOnlyList<TResult> QueryTable<TRow, TResult>(
        TableQuery query,
        Func<TRow, TResult> map)
    {
        var size = 0;
        var status = query(IntPtr.Zero, ref size);
        if (status != ErrorInsufficientBuffer && status != 0)
        {
            return [];
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            status = query(buffer, ref size);
            if (status != 0)
            {
                return [];
            }

            var count = Marshal.ReadInt32(buffer);
            var rowPointer = IntPtr.Add(buffer, sizeof(int));
            var rowSize = Marshal.SizeOf<TRow>();
            var rows = new List<TResult>(count);
            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<TRow>(rowPointer);
                if (row is not null)
                {
                    rows.Add(map(row));
                }

                rowPointer = IntPtr.Add(rowPointer, rowSize);
            }

            return rows;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int DecodePort(uint port)
    {
        var bytes = BitConverter.GetBytes(port);
        return (bytes[0] << 8) + bytes[1];
    }

    private static bool IsLoopback(string address)
    {
        return address is "127.0.0.1" or "::1";
    }

    private delegate int TableQuery(IntPtr buffer, ref int bufferLength);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(
        IntPtr table,
        ref int bufferLength,
        bool sort,
        int ipVersion,
        TcpTableClass tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedUdpTable(
        IntPtr table,
        ref int bufferLength,
        bool sort,
        int ipVersion,
        UdpTableClass tableClass,
        uint reserved);

    private enum TcpTableClass
    {
        OwnerPidAll = 5
    }

    private enum UdpTableClass
    {
        OwnerPid = 1
    }

    [StructLayout(LayoutKind.Sequential)]
    private sealed class MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public int OwningProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private sealed class MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddress = [];

        public uint LocalScopeId;
        public uint LocalPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddress = [];

        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public int OwningProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private sealed class MibUdpRowOwnerPid
    {
        public uint LocalAddress;
        public uint LocalPort;
        public int OwningProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private sealed class MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddress = [];

        public uint LocalScopeId;
        public uint LocalPort;
        public int OwningProcessId;
    }
}

internal sealed record WindowsTcpRow(
    int ProcessId,
    string AddressFamily,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    TcpState State)
{
    public string LocalEndPoint => $"{LocalAddress}:{LocalPort}";

    public string RemoteEndPoint => $"{RemoteAddress}:{RemotePort}";
}

internal sealed record WindowsUdpRow(
    int ProcessId,
    string AddressFamily,
    string LocalAddress,
    int LocalPort)
{
    public string LocalEndPoint => $"{LocalAddress}:{LocalPort}";
}
