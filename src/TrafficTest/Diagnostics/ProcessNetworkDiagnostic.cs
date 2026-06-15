using System.Net.NetworkInformation;
using System.Text.Json;

namespace TrafficTest;

internal static class ProcessNetworkDiagnostic
{
    public static async Task<int> RunAsync(string label, string defaultProcessName, string[] args)
    {
        var options = Parse(defaultProcessName, args);
        var samples = new Dictionary<ConnectionKey, ProcessTcpConnection>();
        IReadOnlyList<WindowsProcessSnapshot> processes = [];
        IReadOnlyList<WindowsTcpRow> tcpRows = [];
        IReadOnlyList<WindowsUdpRow> udpRows = [];
        var started = DateTimeOffset.Now;
        var deadline = started.AddMilliseconds(options.DurationMilliseconds);

        do
        {
            processes = WindowsProcessQuery.GetByName(options.ProcessName);
            var processIds = processes.Select(process => process.ProcessId).ToHashSet();
            tcpRows = WindowsNetworkTable.GetTcpRowsForProcesses(processIds);
            udpRows = WindowsNetworkTable.GetUdpRowsForProcesses(processIds);

            foreach (var row in tcpRows.Where(row => row.State != TcpState.Listen))
            {
                var process = processes.FirstOrDefault(item => item.ProcessId == row.ProcessId);
                samples[new ConnectionKey(row.ProcessId, row.LocalEndPoint, row.RemoteEndPoint, row.State)] = new ProcessTcpConnection(
                    row.ProcessId,
                    process?.ProcessName ?? row.ProcessId.ToString(),
                    row.AddressFamily,
                    row.LocalEndPoint,
                    row.RemoteEndPoint,
                    row.State.ToString());
            }

            if (DateTimeOffset.Now >= deadline)
            {
                break;
            }

            await Task.Delay(options.IntervalMilliseconds);
        }
        while (true);

        var snapshot = new ProcessNetworkSnapshot(
            label,
            options.ProcessName,
            started,
            DateTimeOffset.Now,
            processes,
            tcpRows
                .Where(row => row.State == TcpState.Listen)
                .OrderBy(row => row.ProcessId)
                .ThenBy(row => row.LocalPort)
                .Select(row => new ProcessTcpListener(row.ProcessId, row.AddressFamily, row.LocalEndPoint))
                .ToArray(),
            udpRows
                .OrderBy(row => row.ProcessId)
                .ThenBy(row => row.LocalPort)
                .Select(row => new ProcessUdpEndpoint(row.ProcessId, row.AddressFamily, row.LocalEndPoint))
                .ToArray(),
            samples.Values
                .OrderBy(row => row.ProcessId)
                .ThenBy(row => row.RemoteEndPoint)
                .ThenBy(row => row.LocalEndPoint)
                .ToArray());

        if (options.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(snapshot, JsonOptions));
        }
        else
        {
            Print(snapshot);
        }

        return snapshot.Processes.Count > 0 ? 0 : 1;
    }

    private static void Print(ProcessNetworkSnapshot snapshot)
    {
        Console.WriteLine($"{snapshot.Label} network diagnostic: {snapshot.ProcessName}");
        Console.WriteLine("processes:");
        foreach (var process in snapshot.Processes)
        {
            Console.WriteLine($"  pid={process.ProcessId} name={process.ProcessName} path={process.ExecutablePath ?? "-"}");
        }

        if (snapshot.Processes.Count == 0)
        {
            Console.WriteLine("  none");
        }

        Console.WriteLine("tcp listeners:");
        foreach (var row in snapshot.TcpListeners)
        {
            Console.WriteLine($"  pid={row.ProcessId} {row.AddressFamily} {row.LocalEndPoint}");
        }

        if (snapshot.TcpListeners.Count == 0)
        {
            Console.WriteLine("  none");
        }

        Console.WriteLine("udp endpoints:");
        foreach (var row in snapshot.UdpEndpoints)
        {
            Console.WriteLine($"  pid={row.ProcessId} {row.AddressFamily} {row.LocalEndPoint}");
        }

        if (snapshot.UdpEndpoints.Count == 0)
        {
            Console.WriteLine("  none");
        }

        Console.WriteLine("tcp connections:");
        foreach (var row in snapshot.TcpConnections)
        {
            Console.WriteLine($"  pid={row.ProcessId} {row.ProcessName} {row.AddressFamily} {row.LocalEndPoint} -> {row.RemoteEndPoint} {row.State}");
        }

        if (snapshot.TcpConnections.Count == 0)
        {
            Console.WriteLine("  none");
        }
    }

    private static ProcessNetworkOptions Parse(string defaultProcessName, string[] args)
    {
        var processName = defaultProcessName;
        var durationMilliseconds = 1000;
        var intervalMilliseconds = 250;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            if (CliOptions.TryReadValue(args, ref i, "--process-name", out var processNameValue))
            {
                processName = processNameValue;
                continue;
            }

            if (CliOptions.TryReadValue(args, ref i, "--duration-ms", out var durationValue))
            {
                durationMilliseconds = CliOptions.ParseNonNegativeInt("--duration-ms", durationValue);
                continue;
            }

            if (CliOptions.TryReadValue(args, ref i, "--interval-ms", out var intervalValue))
            {
                intervalMilliseconds = CliOptions.ParsePositiveInt("--interval-ms", intervalValue);
                continue;
            }

            if (args[i].Equals("--json", StringComparison.OrdinalIgnoreCase))
            {
                json = true;
                continue;
            }

            throw new ArgumentException($"Unknown process network diagnostic option '{args[i]}'.");
        }

        return new ProcessNetworkOptions(processName, durationMilliseconds, intervalMilliseconds, json);
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private sealed record ProcessNetworkOptions(
        string ProcessName,
        int DurationMilliseconds,
        int IntervalMilliseconds,
        bool Json);

    private sealed record ConnectionKey(int ProcessId, string LocalEndPoint, string RemoteEndPoint, TcpState State);

    private sealed record ProcessNetworkSnapshot(
        string Label,
        string ProcessName,
        DateTimeOffset StartedAt,
        DateTimeOffset EndedAt,
        IReadOnlyList<WindowsProcessSnapshot> Processes,
        IReadOnlyList<ProcessTcpListener> TcpListeners,
        IReadOnlyList<ProcessUdpEndpoint> UdpEndpoints,
        IReadOnlyList<ProcessTcpConnection> TcpConnections);

    private sealed record ProcessTcpListener(int ProcessId, string AddressFamily, string LocalEndPoint);

    private sealed record ProcessUdpEndpoint(int ProcessId, string AddressFamily, string LocalEndPoint);

    private sealed record ProcessTcpConnection(
        int ProcessId,
        string ProcessName,
        string AddressFamily,
        string LocalEndPoint,
        string RemoteEndPoint,
        string State);
}
