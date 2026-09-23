using System.Net.Sockets;
using ProxiFyre;

namespace TrafficTest;

internal static class WinDivertBypassDiagnostic
{
    public static async Task<int> RunAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        WinDivertNative.Configure(AppContext.BaseDirectory);

        var configuration = new DynamicAppConfiguration(new AppConfiguration
        {
            Apps = [],
            DisabledApps = [],
            CoreProcessName = "__proxifyre_bypass_probe__"
        });
        var processLookup = new ProcessLookup(
            warningLog: message => Console.Error.WriteLine($"[WARN] {message}"));
        var router = new WinDivertPacketRouter(
            configuration,
            processLookup,
            Console.WriteLine,
            new TrafficCounter(),
            new PacketWakeSignal(),
            TimeProvider.System,
            detailedLogging: false,
            warningLog: message => Console.Error.WriteLine($"[WARN] {message}"));

        var network = WinDivertPacketRouter.OpenNetworkHandle();
        WinDivertHandle? flow = null;
        try
        {
            flow = WinDivertFlowTracker.OpenHandle();
            router.Start(
                AppContext.BaseDirectory,
                timeout.Token,
                network,
                flow);
            network = null!;
            flow = null;
            await Task.Delay(TimeSpan.FromMilliseconds(500), timeout.Token).ConfigureAwait(false);

            using var httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(8)
            };
            using var httpConcurrency = new SemaphoreSlim(10, 10);
            var httpResults = await Task.WhenAll(
                Enumerable.Range(0, 50).Select(async _ =>
                {
                    await httpConcurrency.WaitAsync(timeout.Token).ConfigureAwait(false);
                    try
                    {
                        for (var attempt = 0; attempt < 3; attempt++)
                        {
                            try
                            {
                                using var response = await httpClient.GetAsync(
                                    "https://www.bing.com/",
                                    timeout.Token).ConfigureAwait(false);
                                if (response.StatusCode is >= System.Net.HttpStatusCode.OK
                                    and < System.Net.HttpStatusCode.MultipleChoices)
                                {
                                    return true;
                                }
                            }
                            catch (HttpRequestException)
                            {
                            }
                            catch (OperationCanceledException) when (!timeout.IsCancellationRequested)
                            {
                            }

                            if (attempt < 2)
                            {
                                await Task.Delay(
                                    TimeSpan.FromMilliseconds(150 + (attempt * 150)),
                                    timeout.Token).ConfigureAwait(false);
                            }
                        }

                        return false;
                    }
                    finally
                    {
                        httpConcurrency.Release();
                    }
                })).ConfigureAwait(false);
            var failedHttp = httpResults.Count(success => !success);
            if (failedHttp > 0)
            {
                Console.Error.WriteLine(
                    $"FAIL: {failedHttp}/50 pass-through HTTP requests returned an error status.");
                return 1;
            }

            var stunEndPoint = await StunClient.ResolveEndPointAsync(
                "stun.l.google.com",
                19302,
                AddressFamily.InterNetwork,
                timeout.Token).ConfigureAwait(false);
            var failedStun = 0;
            for (var index = 0; index < 20; index++)
            {
                StunResult? result = null;
                for (var attempt = 0; attempt < 3; attempt++)
                {
                    result = await StunClient.SendBindingRequestAsync(
                        stunEndPoint,
                        AddressFamily.InterNetwork,
                        timeoutMilliseconds: 3000,
                        timeout.Token).ConfigureAwait(false);
                    if (result.Success)
                    {
                        break;
                    }

                    await Task.Delay(
                        TimeSpan.FromMilliseconds(150 + (attempt * 150)),
                        timeout.Token).ConfigureAwait(false);
                }

                if (result is null || !result.Success)
                {
                    failedStun++;
                }
            }

            if (failedStun > 0)
            {
                Console.Error.WriteLine(
                    $"FAIL: {failedStun}/20 pass-through STUN requests failed.");
                return 1;
            }

            Console.WriteLine(
                "PASS: 50 non-target HTTP and 20 UDP requests passed through while WinDivert was active.");
            return 0;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("FAIL: pass-through probe timed out.");
            return 1;
        }
        finally
        {
            network?.Dispose();
            flow?.Dispose();
            await router.DisposeAsync().ConfigureAwait(false);
        }
    }
}
