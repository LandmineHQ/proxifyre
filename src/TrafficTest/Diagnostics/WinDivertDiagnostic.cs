using System.ComponentModel;
using ProxiFyre;

namespace TrafficTest;

internal static class WinDivertDiagnostic
{
    public static int Run()
    {
        try
        {
            WinDivertNative.Configure(AppContext.BaseDirectory);
            using var network = WinDivertPacketRouter.OpenNetworkHandle();
            using var flow = WinDivertFlowTracker.OpenHandle();
            _ = WinDivertNative.TryGetParameter(
                network,
                WinDivertParameter.VersionMajor,
                out var major);
            _ = WinDivertNative.TryGetParameter(
                network,
                WinDivertParameter.VersionMinor,
                out var minor);
            Console.WriteLine(
                $"PASS: WinDivert opened network and flow handles; driver version={major}.{minor}.");
            return 0;
        }
        catch (Win32Exception ex)
        {
            Console.Error.WriteLine(
                $"FAIL: WinDivert could not open the signed driver (Win32 {ex.NativeErrorCode}): {ex.Message}");
            Console.Error.WriteLine(
                "Run this diagnostic from an elevated process and verify that Code Integrity/HVCI/EDR policy permits WinDivert64.sys.");
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAIL: {ex}");
            return 1;
        }
    }
}
