using System.Runtime.InteropServices;

namespace ProxiFyre;

internal enum WfpDecision : uint
{
    Permit = 0,
    Block = 1
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct WfpFlowEvent
{
    public ulong EventId;
    public uint ProcessId;
    public ushort AddressFamily;
    public byte Protocol;
    public byte Reserved;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] LocalAddress;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] RemoteAddress;
    public ushort LocalPort;
    public ushort RemotePort;
    public uint RemoteScopeId;
    public uint Flags;
    public uint InterfaceIndex;
    public uint SubInterfaceIndex;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct WfpVerdict
{
    public ulong EventId;
    public WfpDecision Decision;
    public uint Reserved;
}

internal static class WfpProtocol
{
    public const string DevicePath = @"\\.\ProxiFyreWfp";
    public const ushort AddressFamilyInterNetwork = 2;
    public const ushort AddressFamilyInterNetworkV6 = 23;

    public static readonly uint IoctlGetEvent = CtlCode(0x22, 0x900, 0, 1);
    public static readonly uint IoctlCompleteEvent = CtlCode(0x22, 0x901, 0, 2);

    private static uint CtlCode(uint deviceType, uint function, uint method, uint access)
    {
        return (deviceType << 16) | (access << 14) | (function << 2) | method;
    }
}
