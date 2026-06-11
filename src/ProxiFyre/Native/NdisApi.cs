using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ProxiFyre;

internal static unsafe class NdisApi
{
    public const int AdapterListSize = 32;
    public const int AdapterNameSize = 256;
    public const int EthernetAddressLength = 6;
    public const int MaxEtherFrame = 1514;

    public const uint MstcpFlagSentTunnel = 0x00000001;
    public const uint MstcpFlagRecvTunnel = 0x00000002;
    public const uint PacketFlagOnSend = 0x00000001;
    public const uint PacketFlagOnReceive = 0x00000002;

    private const string DllName = "ndisapi.dll";

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenFilterDriver(string driverName);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void CloseFilterDriver(IntPtr handle);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsDriverLoaded(IntPtr handle);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern uint GetDriverVersion(IntPtr handle);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetTcpipBoundAdaptersInfo(IntPtr handle, ref TcpAdapterList adapters);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadPacket(IntPtr handle, ref EthRequest packet);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadPacketsUnsorted(IntPtr handle, IntPtr* packets, uint packetsNum, out uint packetsSuccess);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SendPacketToMstcp(IntPtr handle, ref EthRequest packet);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SendPacketToAdapter(IntPtr handle, ref EthRequest packet);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetAdapterMode(IntPtr handle, ref AdapterMode mode);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FlushAdapterPacketQueue(IntPtr handle, IntPtr adapter);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetPacketEvent(IntPtr handle, IntPtr adapter, SafeWaitHandle win32Event);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetPacketEvent(IntPtr handle, IntPtr adapter, IntPtr win32Event);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void RecalculateIPChecksum(IntermediateBuffer* packet);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void RecalculateTCPChecksum(IntermediateBuffer* packet);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void RecalculateUDPChecksum(IntermediateBuffer* packet);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct AdapterMode
    {
        public IntPtr AdapterHandle;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct EthRequest
    {
        public IntPtr AdapterHandle;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct TcpAdapterList
    {
        public uint Count;
        public fixed byte Names[AdapterListSize * AdapterNameSize];
        public fixed long Handles[AdapterListSize];
        public fixed uint Mediums[AdapterListSize];
        public fixed byte MacAddresses[AdapterListSize * EthernetAddressLength];
        public fixed ushort Mtus[AdapterListSize];

        public IntPtr GetHandle(int index)
        {
            fixed (long* handles = Handles)
            {
                return (IntPtr)handles[index];
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct IntermediateBuffer
    {
        public IntPtr AdapterOrListFlink;
        public IntPtr ListBlink;
        public uint DeviceFlags;
        public uint Length;
        public uint Flags;
        public uint Dot1q;
        public uint FilterId;
        public fixed uint Reserved[4];
        public fixed byte Data[MaxEtherFrame];
    }
}
