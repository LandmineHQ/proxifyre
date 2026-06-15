using System.Diagnostics;
using System.Text.Json;
using ProxiFyre;

namespace TrafficTest;

internal static class TrafficTestRunner
{
    public static async Task<int> RunAsync(string[] args)
    {
        try
        {
            if (TestHelp.TryRun(args, out var helpExitCode))
            {
                return helpExitCode;
            }

            if (args.Length > 0 && args[0].Equals("uu", StringComparison.OrdinalIgnoreCase))
            {
                return await ProcessNetworkDiagnostic.RunAsync("UU", "uu.exe", args.Skip(1).ToArray());
            }

            if (args.Length > 0 && args[0].Equals("steam", StringComparison.OrdinalIgnoreCase))
            {
                return await ProcessNetworkDiagnostic.RunAsync("Steam", "steamwebhelper.exe", args.Skip(1).ToArray());
            }

            var options = TestOptions.Parse(args);
            return await RunRelayTestAsync(options);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            Console.WriteLine();
            TestHelp.Print();
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            return 1;
        }
    }

    private static async Task<int> RunRelayTestAsync(TestOptions options)
    {
        var root = RepositoryPaths.FindRepositoryRoot(AppContext.BaseDirectory);
        var artifactMoniker = GetCurrentArtifactMoniker();
        var configuration = GetConfigurationName(artifactMoniker);
        var coreDir = Path.Combine(root, "artifacts", "bin", "ProxiFyre", artifactMoniker);
        var testHostSource = Path.Combine(root, "artifacts", "bin", "TrafficTestHost", artifactMoniker, "TrafficTestHost.exe");
        var testHostDir = Path.Combine(root, "artifacts", "tmp", "aot-test-host", DateTime.Now.ToString("yyyyMMdd_HHmmss_fff"));
        var testHostExe = Path.Combine(testHostDir, TrafficTestConstants.DefaultCoreProcessName);
        var configPath = Path.Combine(coreDir, "traffic-test-config.json");
        var logPath = Path.Combine(coreDir, "proxifyre-core.log");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        if (!File.Exists(testHostSource))
        {
            Console.Error.WriteLine($"AOT test host executable not found: {testHostSource}");
            Console.Error.WriteLine($"Run .\\scripts\\proxifyre.ps1 build -Configuration {configuration} before test.");
            return 1;
        }

        if (!Directory.Exists(coreDir))
        {
            Console.Error.WriteLine($"ProxiFyre build output not found: {coreDir}");
            Console.Error.WriteLine($"Run .\\scripts\\proxifyre.ps1 build -Configuration {configuration} before test.");
            return 1;
        }

        var moduleDll = Path.Combine(root, "artifacts", "native", configuration, "ProxiFyre.Module.dll");
        if (!File.Exists(moduleDll))
        {
            Console.Error.WriteLine($"AOT module DLL not found: {moduleDll}");
            Console.Error.WriteLine($"Run .\\scripts\\proxifyre.ps1 build -Configuration {configuration} before test.");
            return 1;
        }

        var stunEndPoint = options.Kind == TestKind.Stun
            ? await StunClient.ResolveEndPointAsync(options.StunHost, options.StunPort, options.StunAddressFamily, cts.Token)
            : null;

        Directory.CreateDirectory(testHostDir);
        CopyTestHostFiles(Path.GetDirectoryName(testHostSource)!, testHostDir);
        File.Copy(testHostSource, testHostExe, overwrite: true);
        File.WriteAllText(logPath, string.Empty);
        File.WriteAllText(
            configPath,
            JsonSerializer.Serialize(
                new
                {
                    coreProcessName = Path.GetFileName(testHostExe),
                    apps = BuildAppPatterns(options)
                },
                new JsonSerializerOptions { WriteIndented = true }));

        Process? testHost = null;
        try
        {
            testHost = StartTestHost(testHostExe, testHostDir);
            await WaitForMainWindowAsync(testHost, cts.Token);
            Console.WriteLine($"AOT test host: {Path.GetFileName(testHostExe)} pid={testHost.Id}");

            using var module = new AotModuleTestController(configPath, logPath, Console.WriteLine);
            await module.LoadAndRunAsync(
                testHost.Id,
                Path.GetFileName(testHostExe),
                testHostExe,
                BuildAppPatterns(options),
                LicenseKey.CreateKey(LicenseKey.GetCurrentDeviceId()),
                cts.Token).ConfigureAwait(false);
            await WaitForCoreReadyAsync(logPath, cts.Token);

            var result = options.Kind == TestKind.Curl
                ? await CurlTest.RunAsync(options, root, cts.Token)
                : await StunBindingTest.RunAsync(options, stunEndPoint!, cts.Token);

            await Task.Delay(TimeSpan.FromSeconds(1), cts.Token);
            var failed = !result.Success;
            CoreLogReporter.PrintLogSummary(logPath, includeRelevantLines: options.Detailed || failed);

            return result.Success ? 0 : 1;
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
        finally
        {
            if (testHost is { HasExited: false })
            {
                testHost.Kill(entireProcessTree: true);
                await testHost.WaitForExitAsync();
            }

            testHost?.Dispose();
            TryDeleteDirectory(testHostDir);
        }
    }

    private static string GetCurrentArtifactMoniker()
    {
        var baseDirectory = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var directoryName = Path.GetFileName(baseDirectory);
        return string.IsNullOrWhiteSpace(directoryName)
            ? "debug_win-x64"
            : directoryName;
    }

    private static string GetConfigurationName(string artifactMoniker)
    {
        return artifactMoniker.StartsWith("release_", StringComparison.OrdinalIgnoreCase)
            ? "Release"
            : "Debug";
    }

    private static Process StartTestHost(string testHostExe, string testHostDir)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = testHostExe,
                WorkingDirectory = testHostDir,
                UseShellExecute = false
            }
        };

        if (!process.Start())
        {
            process.Dispose();
            throw new InvalidOperationException($"Failed to start AOT test host: {testHostExe}");
        }

        return process;
    }

    private static async Task WaitForCoreReadyAsync(string logPath, CancellationToken cancellationToken)
    {
        await CoreLogReporter.WaitForLogLineAsync(logPath, "Packet filter started.", TimeSpan.FromSeconds(15), cancellationToken);
        await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
    }

    private static async Task WaitForMainWindowAsync(Process process, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (process.HasExited)
            {
                throw new InvalidOperationException($"AOT test host exited early with code {process.ExitCode}.");
            }

            process.Refresh();
            if (process.MainWindowHandle != nint.Zero)
            {
                return;
            }

            await Task.Delay(100, cancellationToken);
        }

        throw new TimeoutException("Timed out waiting for AOT test host window.");
    }

    private static void CopyTestHostFiles(string sourceDirectory, string targetDirectory)
    {
        foreach (var file in Directory.EnumerateFiles(sourceDirectory))
        {
            var fileName = Path.GetFileName(file);
            if (fileName.Equals("TrafficTestHost.exe", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            File.Copy(file, Path.Combine(targetDirectory, fileName), overwrite: true);
        }
    }

    private static void TryDeleteDirectory(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch
        {
        }
    }

    private static string[] BuildAppPatterns(TestOptions options)
    {
        return options.Kind switch
        {
            TestKind.Curl => ["curl.exe"],
            TestKind.Stun => [ProcessIdentity.GetCurrentExecutableName()],
            _ => throw new ArgumentOutOfRangeException(nameof(options))
        };
    }
}
