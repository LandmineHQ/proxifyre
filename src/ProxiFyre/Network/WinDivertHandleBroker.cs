using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ProxiFyre;

internal readonly record struct BrokeredWinDivertHandles(nint Network, nint Flow);

internal static class WinDivertHandleBroker
{
    private const uint ProcessDuplicateHandle = 0x0040;
    private const uint DuplicateSameAccess = 0x00000002;
    private const uint DuplicateCloseSource = 0x00000001;

    public static BrokeredWinDivertHandles OpenForTarget(int processId)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("WinDivert handle brokering requires Windows.");
        }

        WinDivertNative.Configure(AppContext.BaseDirectory);
        var processHandle = OpenProcess(ProcessDuplicateHandle, false, processId);
        if (processHandle == nint.Zero)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Could not open target process {processId} for WinDivert handle duplication.");
        }

        nint network = 0;
        nint flow = 0;
        try
        {
            using var sourceNetwork = WinDivertPacketRouter.OpenNetworkHandle();
            network = DuplicateToTarget(
                processHandle,
                sourceNetwork.DangerousGetHandle(),
                "network");

            try
            {
                using var sourceFlow = WinDivertFlowTracker.OpenHandle();
                flow = DuplicateToTarget(
                    processHandle,
                    sourceFlow.DangerousGetHandle(),
                    "flow");
            }
            catch
            {
                CloseTargetHandle(processHandle, network);
                network = 0;
                throw;
            }

            return new BrokeredWinDivertHandles(network, flow);
        }
        finally
        {
            _ = CloseHandle(processHandle);
        }
    }

    public static void CloseForTarget(int processId, BrokeredWinDivertHandles handles)
    {
        if (handles.Network == 0 && handles.Flow == 0)
        {
            return;
        }

        var processHandle = OpenProcess(ProcessDuplicateHandle, false, processId);
        if (processHandle == nint.Zero)
        {
            return;
        }

        try
        {
            CloseTargetHandle(processHandle, handles.Network);
            CloseTargetHandle(processHandle, handles.Flow);
        }
        finally
        {
            _ = CloseHandle(processHandle);
        }
    }

    private static nint DuplicateToTarget(nint processHandle, nint sourceHandle, string name)
    {
        if (!DuplicateHandle(
                GetCurrentProcess(),
                sourceHandle,
                processHandle,
                out var duplicate,
                0,
                false,
                DuplicateSameAccess))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Could not duplicate the WinDivert {name} handle into the target process.");
        }

        return duplicate;
    }

    private static void CloseTargetHandle(nint processHandle, nint targetHandle)
    {
        if (targetHandle == 0)
        {
            return;
        }

        _ = DuplicateHandle(
            processHandle,
            targetHandle,
            nint.Zero,
            out _,
            0,
            false,
            DuplicateCloseSource);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        nint sourceProcessHandle,
        nint sourceHandle,
        nint targetProcessHandle,
        out nint targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);
}
