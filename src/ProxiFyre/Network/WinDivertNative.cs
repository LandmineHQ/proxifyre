using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProxiFyre;

internal enum WinDivertParameter
{
    QueueLength = 0,
    QueueTime = 1,
    QueueSize = 2,
    VersionMajor = 3,
    VersionMinor = 4
}

internal enum WinDivertShutdown
{
    Receive = 1,
    Send = 2,
    Both = 3
}

[Flags]
internal enum WinDivertOpenFlags : ulong
{
    None = 0,
    Sniff = 0x0001,
    Drop = 0x0002,
    ReceiveOnly = 0x0004,
    SendOnly = 0x0008,
    NoInstall = 0x0010,
    Fragments = 0x0020
}

internal sealed class WinDivertHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal WinDivertHandle(nint handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        return WinDivertNative.Close(handle);
    }
}

internal static class WinDivertNative
{
    internal const int ErrorAccessDenied = 5;
    internal const int ErrorFileNotFound = 2;
    internal const int ErrorNoData = 232;
    internal const int ErrorOperationAborted = 995;
    private const string WinDivertDllSha256 = "C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2";
    private const string WinDivertDriverSha256 = "8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2";

    private static readonly object Sync = new();
    private static string? _nativeDirectory;
    private static bool _resolverRegistered;

    public static void Configure(string? nativeDirectory = null)
    {
        var resolvedDirectory = ResolveNativeDirectory(nativeDirectory);
        VerifyNativeAssets(resolvedDirectory);
        lock (Sync)
        {
            if (_nativeDirectory is not null
                && !string.Equals(_nativeDirectory, resolvedDirectory, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"WinDivert native directory was already initialized as '{_nativeDirectory}'.");
            }

            _nativeDirectory = resolvedDirectory;
            if (_resolverRegistered)
            {
                return;
            }

            NativeLibrary.SetDllImportResolver(
                typeof(WinDivertNative).Assembly,
                ResolveDllImport);
            _resolverRegistered = true;
        }
    }

    public static WinDivertHandle Open(
        string filter,
        WinDivertLayer layer,
        short priority = 0,
        WinDivertOpenFlags flags = WinDivertOpenFlags.None)
    {
        Configure();
        var filterBytes = Encoding.ASCII.GetBytes(filter + '\0');
        var handle = OpenNative(filterBytes, layer, priority, (ulong)flags);
        if (handle == nint.Zero || handle == new nint(-1))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"WinDivertOpen failed for layer={layer}, filter='{filter}'.");
        }

        return new WinDivertHandle(handle);
    }

    public static bool TryReceive(
        WinDivertHandle handle,
        byte[] packet,
        out int packetLength,
        out WinDivertAddress address,
        out int error)
    {
        packetLength = 0;
        address = default;
        var receiveLength = 0u;
        var success = ReceiveNative(
            handle,
            packet,
            (uint)packet.Length,
            ref receiveLength,
            ref address);
        if (!success)
        {
            error = Marshal.GetLastWin32Error();
            return false;
        }

        packetLength = checked((int)receiveLength);
        error = 0;
        return true;
    }

    public static unsafe bool TrySend(
        WinDivertHandle handle,
        ReadOnlySpan<byte> packet,
        in WinDivertAddress address,
        out int error)
    {
        var sendLength = 0u;
        var localAddress = address;
        bool success;
        fixed (byte* packetPtr = packet)
        {
            success = SendNative(
                handle,
                packetPtr,
                (uint)packet.Length,
                ref sendLength,
                ref localAddress);
        }

        if (!success || sendLength != packet.Length)
        {
            error = Marshal.GetLastWin32Error();
            return false;
        }

        error = 0;
        return true;
    }

    public static void ShutdownReceive(WinDivertHandle handle)
    {
        _ = ShutdownNative(handle, WinDivertShutdown.Receive);
    }

    public static bool TrySetParameter(
        WinDivertHandle handle,
        WinDivertParameter parameter,
        ulong value)
    {
        return SetParameterNative(handle, parameter, value);
    }

    public static bool TryGetParameter(
        WinDivertHandle handle,
        WinDivertParameter parameter,
        out ulong value)
    {
        return GetParameterNative(handle, parameter, out value);
    }

    private static nint ResolveDllImport(
        string libraryName,
        Assembly assembly,
        DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, "WinDivert.dll", StringComparison.OrdinalIgnoreCase))
        {
            return nint.Zero;
        }

        lock (Sync)
        {
            if (_nativeDirectory is null)
            {
                return nint.Zero;
            }

            var path = Path.Combine(_nativeDirectory, "WinDivert.dll");
            return File.Exists(path) ? NativeLibrary.Load(path, assembly, searchPath) : nint.Zero;
        }
    }

    private static string ResolveNativeDirectory(string? requestedDirectory)
    {
        if (!string.IsNullOrWhiteSpace(requestedDirectory))
        {
            var fullPath = Path.GetFullPath(requestedDirectory);
            if (!File.Exists(Path.Combine(fullPath, "WinDivert.dll")))
            {
                throw new FileNotFoundException(
                    "WinDivert.dll was not found in the requested native directory.",
                    Path.Combine(fullPath, "WinDivert.dll"));
            }

            return fullPath;
        }

        var baseDirectory = AppContext.BaseDirectory;
        var baseDll = Path.Combine(baseDirectory, "WinDivert.dll");
        if (File.Exists(baseDll))
        {
            return baseDirectory;
        }

        throw new FileNotFoundException(
            "WinDivert.dll was not found next to the running application.",
            baseDll);
    }

    private static void VerifyNativeAssets(string nativeDirectory)
    {
        VerifyHash(
            Path.Combine(nativeDirectory, "WinDivert.dll"),
            WinDivertDllSha256);
        VerifyHash(
            Path.Combine(nativeDirectory, "WinDivert64.sys"),
            WinDivertDriverSha256);
    }

    private static void VerifyHash(string path, string expectedHex)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                "Required WinDivert native asset is missing.",
                path);
        }

        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.SequentialScan);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!actual.Equals(expectedHex, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"WinDivert native asset hash mismatch for '{path}'. Expected {expectedHex}, actual {actual}.");
        }
    }

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertOpen", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    private static extern nint OpenNative(
        byte[] filter,
        WinDivertLayer layer,
        short priority,
        ulong flags);

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertRecv", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReceiveNative(
        WinDivertHandle handle,
        [Out] byte[] packet,
        uint packetLength,
        ref uint receiveLength,
        ref WinDivertAddress address);

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertSend", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool SendNative(
        WinDivertHandle handle,
        byte* packet,
        uint packetLength,
        ref uint sendLength,
        ref WinDivertAddress address);

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertShutdown", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShutdownNative(
        WinDivertHandle handle,
        WinDivertShutdown shutdown);

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertSetParam", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetParameterNative(
        WinDivertHandle handle,
        WinDivertParameter parameter,
        ulong value);

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertGetParam", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetParameterNative(
        WinDivertHandle handle,
        WinDivertParameter parameter,
        out ulong value);

    internal static bool Close(nint handle)
    {
        return CloseNativeCore(handle);
    }

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertClose", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseNativeCore(nint handle);
}
