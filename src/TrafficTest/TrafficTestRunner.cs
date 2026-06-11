using System.Diagnostics;
using System.Text.Json;

namespace TrafficTest;

internal static class TrafficTestRunner
{
    public static async Task<int> RunAsync(string[] args)
    {
        var options = TestOptions.Parse(args);
        var root = RepositoryPaths.FindRepositoryRoot(AppContext.BaseDirectory);
        var coreDir = Path.Combine(root, "src", "ProxiFyre", "bin", "Debug", "net10.0-windows", "win-x64");
        var coreExe = Path.Combine(coreDir, "ProxiFyre.exe");
        var coreAlias = Path.Combine(coreDir, TrafficTestConstants.DefaultCoreProcessName);
        var configPath = Path.Combine(coreDir, "traffic-test-config.json");
        var logPath = Path.Combine(coreDir, "proxifyre-core.log");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        if (options.Kind == TestKind.StunScan)
        {
            return await StunScanTest.RunAsync(options, cts.Token);
        }

        if (options.Kind == TestKind.StunSeriesChild)
        {
            return await StunSeriesTest.RunChildAsync(options, cts.Token);
        }

        if (!File.Exists(coreExe))
        {
            Console.Error.WriteLine($"Core executable not found: {coreExe}");
            return 1;
        }

        var appPatterns = BuildAppPatterns(options);
        var stunEndPoint = options.RequiresStunEndPoint
            ? await StunClient.ResolveEndPointAsync(options.StunHost, options.StunPort, options.StunAddressFamily, cts.Token)
            : null;

        File.Copy(coreExe, coreAlias, overwrite: true);
        File.WriteAllText(logPath, string.Empty);
        File.WriteAllText(
            configPath,
            JsonSerializer.Serialize(
                new
                {
                    coreProcessName = Path.GetFileName(coreAlias),
                    apps = appPatterns
                },
                new JsonSerializerOptions { WriteIndented = true }));

        Process? core = null;
        Task? coreOutputPump = null;
        var coreOutput = new BoundedLog(160);
        try
        {
            if (options.Kind == TestKind.StunBenchmark)
            {
                var directAlias = ProcessIdentity.CreateTrafficTestAlias();
                var direct = await StunSeriesTest.RunNamedDirectAsync(directAlias, options, cts.Token);
                if (!direct.HasSamples)
                {
                    Console.WriteLine("Skipping relay benchmark because named direct baseline did not produce samples.");
                    return 1;
                }

                core = StartCore(coreAlias, configPath, coreDir, options, coreOutput, cts.Token, out coreOutputPump);
                await WaitForCoreReadyAsync(logPath, cts.Token);

                var relayProbe = await StunSeriesTest.RunProbeAsync("proxifyre relay preflight", options, stunEndPoint!, cts.Token);
                if (!relayProbe.Success)
                {
                    Console.WriteLine($"Skipping benchmark because relay STUN preflight failed: {relayProbe.Error}");
                    CoreLogReporter.PrintLogSummary(logPath, includeRelevantLines: true);
                    CoreLogReporter.PrintTrafficSummary(coreOutput.Snapshot());
                    return 1;
                }

                var relay = await StunSeriesTest.RunAsync("proxifyre relay", options, stunEndPoint!, cts.Token);
                await Task.Delay(TimeSpan.FromSeconds(1), cts.Token);
                StunSeriesTest.PrintBenchmarkSummary(direct, relay);
                CoreLogReporter.PrintLogSummary(logPath, includeRelevantLines: options.Detailed || !relay.HasSamples);
                CoreLogReporter.PrintTrafficSummary(coreOutput.Snapshot());
                return direct.HasSamples && relay.HasSamples ? 0 : 1;
            }

            core = StartCore(coreAlias, configPath, coreDir, options, coreOutput, cts.Token, out coreOutputPump);
            await WaitForCoreReadyAsync(logPath, cts.Token);

            if (options.Kind == TestKind.StunRelayScan)
            {
                var relayScanExitCode = await StunScanTest.RunAsync(options, cts.Token);
                await Task.Delay(TimeSpan.FromSeconds(1), cts.Token);
                CoreLogReporter.PrintLogSummary(logPath, includeRelevantLines: options.Detailed || relayScanExitCode != 0);
                CoreLogReporter.PrintTrafficSummary(coreOutput.Snapshot());
                return relayScanExitCode;
            }

            var result = options.Kind == TestKind.Curl
                ? await CurlTest.RunAsync(options, root, cts.Token)
                : await StunBindingTest.RunAsync(options, stunEndPoint!, cts.Token);

            await Task.Delay(TimeSpan.FromSeconds(1), cts.Token);
            var failed = !result.Success;
            CoreLogReporter.PrintLogSummary(logPath, includeRelevantLines: options.Detailed || failed);
            CoreLogReporter.PrintTrafficSummary(coreOutput.Snapshot());
            if (failed && !options.Detailed)
            {
                Console.WriteLine("captured core output tail:");
                foreach (var line in coreOutput.Snapshot())
                {
                    Console.WriteLine(line);
                }
            }

            return result.Success ? 0 : 1;
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
        finally
        {
            if (core is { HasExited: false })
            {
                core.Kill(entireProcessTree: true);
                await core.WaitForExitAsync();
            }

            if (coreOutputPump is not null)
            {
                try
                {
                    await coreOutputPump.WaitAsync(TimeSpan.FromSeconds(2));
                }
                catch
                {
                }
            }

            core?.Dispose();
        }
    }

    private static Process StartCore(
        string coreAlias,
        string configPath,
        string coreDir,
        TestOptions options,
        BoundedLog coreOutput,
        CancellationToken cancellationToken,
        out Task coreOutputPump)
    {
        var core = ProcessRunner.Start(
            coreAlias,
            $"--run --config \"{configPath}\"{(options.Detailed ? " --detailed" : string.Empty)}",
            coreDir,
            redirect: true);
        Console.WriteLine($"Core process: {Path.GetFileName(coreAlias)} pid={core.Id}");
        Console.WriteLine($"Observe network usage on this process, not on ProxiFyre.exe: {Path.GetFileName(coreAlias)}");
        coreOutputPump = ProcessRunner.CaptureProcessOutputAsync(core, coreOutput, options.Detailed, cancellationToken);
        return core;
    }

    private static async Task WaitForCoreReadyAsync(string logPath, CancellationToken cancellationToken)
    {
        await CoreLogReporter.WaitForLogLineAsync(logPath, "Packet filter started.", TimeSpan.FromSeconds(15), cancellationToken);
        await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
    }

    private static string[] BuildAppPatterns(TestOptions options)
    {
        return options.Kind switch
        {
            TestKind.Curl => ["curl.exe"],
            TestKind.Stun or TestKind.StunBenchmark or TestKind.StunRelayScan => [ProcessIdentity.GetCurrentExecutableName()],
            _ => throw new ArgumentOutOfRangeException(nameof(options))
        };
    }
}
