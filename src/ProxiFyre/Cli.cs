namespace ProxiFyre;

using System.IO;

internal static class Cli
{
    public static async Task<int> RunAsync(string[] args)
    {
        AttachConsole();

        if (args.Any(IsHelp))
        {
            PrintUsage();
            return 0;
        }

        if (args.Any(a => string.Equals(a, "--license-device", StringComparison.OrdinalIgnoreCase)))
        {
            if (args.Length != 1)
            {
                Console.Error.WriteLine("Usage: ProxiFyre.exe --license-device");
                return 2;
            }

            PrintLicense(LicenseKey.GetCurrentDeviceId());
            return 0;
        }

        var licenseDeviceId = GetOptionValue(args, "--license-key");
        if (licenseDeviceId is not null)
        {
            if (args.Length != 2 || LicenseKey.NormalizeDeviceId(licenseDeviceId).Length == 0)
            {
                Console.Error.WriteLine("Usage: ProxiFyre.exe --license-key <device-id>");
                return 2;
            }

            PrintLicense(licenseDeviceId);
            return 0;
        }

        Console.WriteLine("ProxiFyre WinDivert relay");

        var configPath = GetConfigPath(args);

        if (args.Any(a => string.Equals(a, "--init-config", StringComparison.OrdinalIgnoreCase)))
        {
            AppConfiguration.WriteSample(configPath);
            Console.WriteLine($"Wrote sample configuration: {configPath}");
            return 0;
        }

        var appToAdd = GetOptionValue(args, "--add-app");
        if (!string.IsNullOrWhiteSpace(appToAdd))
        {
            var apps = AppConfiguration.AddApp(configPath, appToAdd);
            Console.WriteLine($"Added application pattern: {appToAdd}");
            Console.WriteLine($"Configuration: {configPath}");
            Console.WriteLine($"Applications: {string.Join(", ", apps)}");
            return 0;
        }

        if (!args.Any(a => string.Equals(a, "--run", StringComparison.OrdinalIgnoreCase)))
        {
            PrintUsage();
            return 0;
        }

        try
        {
            using var logger = CoreLogger.CreateForCurrentProcess();
            var configuration = AppConfiguration.Load(configPath);
            var detailedLogging = configuration.Detailed
                || args.Any(a => string.Equals(a, "--detailed", StringComparison.OrdinalIgnoreCase));
            logger.Info($"Configuration path: {configPath}");
            logger.Info($"Relay network activity process: {System.Diagnostics.Process.GetCurrentProcess().ProcessName}.exe");
            logger.Info($"Detailed logging: {(detailedLogging ? "enabled" : "disabled")}");
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            await using var service = new RelayService(
                logger.Info,
                detailedLogging,
                PrintTraffic,
                warningLog: logger.Warning);
            service.Start(configuration, configPath, cts.Token);
            logger.Info("Running. Press Ctrl+C to stop.");

            try
            {
                await Task.WhenAny(Task.Delay(Timeout.InfiniteTimeSpan, cts.Token), service.Completion);
            }
            catch (OperationCanceledException)
            {
            }

            await service.StopAsync();
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            try
            {
                using var logger = CoreLogger.CreateForCurrentProcess();
                logger.Error($"Fatal startup error: {ex}");
            }
            catch
            {
            }

            return 1;
        }
    }

    public static string GetConfigPath(string[] args)
    {
        return Path.GetFullPath(GetOptionValue(args, "--config") ?? Path.Combine(AppContext.BaseDirectory, "app-config.json"));
    }

    private static string? GetOptionValue(string[] args, string optionName)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], optionName, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }

        return null;
    }

    private static bool IsHelp(string arg)
    {
        return string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "-h", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "/?", StringComparison.OrdinalIgnoreCase);
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  ProxiFyre.exe");
        Console.WriteLine("  ProxiFyre.exe --run [--config <path>] [--detailed]");
        Console.WriteLine("  ProxiFyre.exe --license-device");
        Console.WriteLine("  ProxiFyre.exe --license-key <device-id>");
        Console.WriteLine("  ProxiFyre.exe --add-app <exe-or-path> [--config <path>]");
        Console.WriteLine("  ProxiFyre.exe --init-config [--config <path>]");
    }

    private static void PrintLicense(string deviceId)
    {
        Console.WriteLine($"deviceId={LicenseKey.NormalizeDeviceId(deviceId)}");
        Console.WriteLine($"licenseKey={LicenseKey.CreateKey(deviceId)}");
    }

    private static void PrintTraffic(TrafficSnapshot snapshot)
    {
        Console.WriteLine(
            $"TRAFFIC up={snapshot.UploadBytes} down={snapshot.DownloadBytes} " +
            $"upRate={snapshot.UploadBytesPerSecond} downRate={snapshot.DownloadBytesPerSecond}");
    }

    private static void AttachConsole()
    {
        try
        {
            NativeConsole.AttachConsole(-1);
        }
        catch
        {
        }
    }

    private static class NativeConsole
    {
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern bool AttachConsole(int processId);
    }
}

