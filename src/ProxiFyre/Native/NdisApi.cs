using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ProxiFyre;

internal static unsafe class NdisApi
{
    private const uint DriverDesiredAccess = 0;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileDeviceNdisrd = 0x00008300;
    private const uint NdisrdIoctlIndex = 0x830;
    private const uint MethodBuffered = 0;
    private const uint FileAnyAccess = 0;
    private static readonly IntPtr InvalidHandleValue = new(-1);

    private static readonly uint IoctlGetVersion = CtlCode(FileDeviceNdisrd, NdisrdIoctlIndex, MethodBuffered, FileAnyAccess);
    private static readonly uint IoctlGetTcpipInterfaces = CtlCode(FileDeviceNdisrd, NdisrdIoctlIndex + 1, MethodBuffered, FileAnyAccess);
    private static readonly uint IoctlSendPacketToAdapter = CtlCode(FileDeviceNdisrd, NdisrdIoctlIndex + 2, MethodBuffered, FileAnyAccess);
    private static readonly uint IoctlSendPacketToMstcp = CtlCode(FileDeviceNdisrd, NdisrdIoctlIndex + 3, MethodBuffered, FileAnyAccess);
    private static readonly uint IoctlReadPacket = CtlCode(FileDeviceNdisrd, NdisrdIoctlIndex + 4, MethodBuffered, FileAnyAccess);
    private static readonly uint IoctlSetAdapterMode = CtlCode(FileDeviceNdisrd, NdisrdIoctlIndex + 5, MethodBuffered, FileAnyAccess);
    private static readonly uint IoctlFlushAdapterQueue = CtlCode(FileDeviceNdisrd, NdisrdIoctlIndex + 6, MethodBuffered, FileAnyAccess);
    private static readonly uint IoctlSetEvent = CtlCode(FileDeviceNdisrd, NdisrdIoctlIndex + 7, MethodBuffered, FileAnyAccess);
    private static readonly uint IoctlReadPacketsUnsorted = CtlCode(FileDeviceNdisrd, NdisrdIoctlIndex + 25, MethodBuffered, FileAnyAccess);

    public const int AdapterListSize = 32;
    public const int AdapterNameSize = 256;
    public const int EthernetAddressLength = 6;
    public const int MaxEtherFrame = 1514;

    public const uint MstcpFlagSentTunnel = 0x00000001;
    public const uint MstcpFlagRecvTunnel = 0x00000002;
    public const uint PacketFlagOnSend = 0x00000001;
    public const uint PacketFlagOnReceive = 0x00000002;

    public static int LastWin32Error => Marshal.GetLastWin32Error();

    public static IntPtr OpenFilterDriver(string driverName)
    {
        var handle = CreateFile(
            $@"\\.\{driverName}",
            DriverDesiredAccess,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOverlapped,
            IntPtr.Zero);

        return handle == InvalidHandleValue ? IntPtr.Zero : handle;
    }

    public static void CloseFilterDriver(IntPtr handle)
    {
        if (handle != IntPtr.Zero && handle != InvalidHandleValue)
        {
            CloseHandle(handle);
        }
    }

    public static bool IsDriverLoaded(IntPtr handle) => handle != IntPtr.Zero && handle != InvalidHandleValue;

    public static uint GetDriverVersion(IntPtr handle)
    {
        var version = 0xFFFFFFFFu;
        return DeviceIoControl(handle, IoctlGetVersion, &version, sizeof(uint), &version, sizeof(uint), out _, IntPtr.Zero)
            ? version
            : 0;
    }

    public static bool GetTcpipBoundAdaptersInfo(IntPtr handle, ref TcpAdapterList adapters)
    {
        fixed (TcpAdapterList* adapterPtr = &adapters)
        {
            var size = (uint)sizeof(TcpAdapterList);
            return DeviceIoControl(handle, IoctlGetTcpipInterfaces, null, 0, adapterPtr, size, out _, IntPtr.Zero);
        }
    }

    public static bool ReadPacket(IntPtr handle, ref EthRequest packet)
    {
        fixed (EthRequest* packetPtr = &packet)
        {
            var size = (uint)sizeof(EthRequest);
            return DeviceIoControl(handle, IoctlReadPacket, packetPtr, size, null, 0, out _, IntPtr.Zero);
        }
    }

    public static bool ReadPacketsUnsorted(IntPtr handle, IntPtr* packets, uint packetsNum, out uint packetsSuccess)
    {
        packetsSuccess = 0;
        if (packetsNum != 1)
        {
            throw new NotSupportedException("The direct NDISRD wrapper currently supports one packet per read.");
        }

        var request = new EthMRequestOne
        {
            AdapterHandle = IntPtr.Zero,
            PacketsNumber = 1,
            Packet0 = packets[0]
        };

        var ok = DeviceIoControl(handle, IoctlReadPacketsUnsorted, &request, (uint)sizeof(EthMRequestOne), &request, (uint)sizeof(EthMRequestOne), out _, IntPtr.Zero);
        packetsSuccess = request.PacketsSuccess;
        return ok;
    }

    public static bool SendPacketToMstcp(IntPtr handle, ref EthRequest packet)
    {
        fixed (EthRequest* packetPtr = &packet)
        {
            return DeviceIoControl(handle, IoctlSendPacketToMstcp, packetPtr, (uint)sizeof(EthRequest), null, 0, out _, IntPtr.Zero);
        }
    }

    public static bool SendPacketToAdapter(IntPtr handle, ref EthRequest packet)
    {
        fixed (EthRequest* packetPtr = &packet)
        {
            return DeviceIoControl(handle, IoctlSendPacketToAdapter, packetPtr, (uint)sizeof(EthRequest), null, 0, out _, IntPtr.Zero);
        }
    }

    public static bool SetAdapterMode(IntPtr handle, ref AdapterMode mode)
    {
        fixed (AdapterMode* modePtr = &mode)
        {
            return DeviceIoControl(handle, IoctlSetAdapterMode, modePtr, (uint)sizeof(AdapterMode), null, 0, out _, IntPtr.Zero);
        }
    }

    public static bool FlushAdapterPacketQueue(IntPtr handle, IntPtr adapter)
    {
        return DeviceIoControl(handle, IoctlFlushAdapterQueue, &adapter, (uint)sizeof(IntPtr), null, 0, out _, IntPtr.Zero);
    }

    public static bool SetPacketEvent(IntPtr handle, IntPtr adapter, SafeWaitHandle win32Event)
    {
        return SetPacketEvent(handle, adapter, win32Event.DangerousGetHandle());
    }

    public static bool SetPacketEvent(IntPtr handle, IntPtr adapter, IntPtr win32Event)
    {
        var adapterEvent = new AdapterEvent
        {
            AdapterHandle = adapter,
            EventHandle = win32Event
        };

        return DeviceIoControl(handle, IoctlSetEvent, &adapterEvent, (uint)sizeof(AdapterEvent), null, 0, out _, IntPtr.Zero);
    }

    private static uint CtlCode(uint deviceType, uint function, uint method, uint access)
    {
        return (deviceType << 16) | (access << 14) | (function << 2) | method;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        IntPtr device,
        uint ioControlCode,
        void* inBuffer,
        uint inBufferSize,
        void* outBuffer,
        uint outBufferSize,
        out uint bytesReturned,
        IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

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
    private struct EthMRequestOne
    {
        public IntPtr AdapterHandle;
        public uint PacketsNumber;
        public uint PacketsSuccess;
        public IntPtr Packet0;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct AdapterEvent
    {
        public IntPtr AdapterHandle;
        public IntPtr EventHandle;
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
