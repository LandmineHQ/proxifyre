using System.Net.Sockets;
using ProxiFyre;

namespace TrafficTest;

internal static class WinDivertBypassDiagnostic
{
    public static async Task<int> RunAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        WinDivertNative.Configure(AppContext.BaseDirectory);

        var configuration = new DynamicAppConfiguration(new AppConfiguration
        {
            Apps = [],
            DisabledApps = [],
            CoreProcessName = "__proxifyre_bypass_probe__"
        });
        var processLookup = new ProcessLookup();
        var router = new WinDivertPacketRouter(
            configuration,
            processLookup,
            Console.WriteLine,
            new TrafficCounter(),
            new PacketWakeSignal(),
            TimeProvider.System,
            detailedLogging: false);

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
            var httpResults = await Task.WhenAll(
                Enumerable.Range(0, 50).Select(async _ =>
                {
                    using var response = await httpClient.GetAsync(
                        "https://www.bing.com/",
                        timeout.Token).ConfigureAwait(false);
                    return response.StatusCode;
                })).ConfigureAwait(false);
            var failedHttp = httpResults.Count(status =>
                status is < System.Net.HttpStatusCode.OK
                    or >= System.Net.HttpStatusCode.MultipleChoices);
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
            var stunResults = await Task.WhenAll(
                Enumerable.Range(0, 20).Select(_ =>
                    StunClient.SendBindingRequestAsync(
                        stunEndPoint,
                        AddressFamily.InterNetwork,
                        timeoutMilliseconds: 3000,
                        timeout.Token))).ConfigureAwait(false);
            var failedStun = stunResults.Count(result => !result.Success);
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
