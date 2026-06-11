using ProxiFyre;

namespace TrafficTest;

internal static class LicenseCommand
{
    public static bool TryRun(string[] args, out int exitCode)
    {
        exitCode = 0;
        if (args.Length == 0)
        {
            return false;
        }

        var mode = args[0].Trim();
        if (mode.Equals("license-device", StringComparison.OrdinalIgnoreCase))
        {
            if (args.Length != 1)
            {
                Console.Error.WriteLine("Usage: license-device");
                exitCode = 2;
                return true;
            }

            var deviceId = LicenseKey.GetCurrentDeviceId();
            PrintLicense(deviceId);
            return true;
        }

        if (mode.Equals("license-key", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryGetDeviceId(args, out var deviceId))
            {
                Console.Error.WriteLine("Usage: license-key <device-id>");
                exitCode = 2;
                return true;
            }

            PrintLicense(deviceId);
            return true;
        }

        return false;
    }

    private static bool TryGetDeviceId(string[] args, out string deviceId)
    {
        deviceId = string.Empty;
        if (args.Length != 2)
        {
            return false;
        }

        var normalized = LicenseKey.NormalizeDeviceId(args[1]);
        if (normalized.Length == 0)
        {
            return false;
        }

        deviceId = args[1].Trim();
        return true;
    }

    private static void PrintLicense(string deviceId)
    {
        Console.WriteLine($"deviceId={LicenseKey.NormalizeDeviceId(deviceId)}");
        Console.WriteLine($"licenseKey={LicenseKey.CreateKey(deviceId)}");
    }
}
