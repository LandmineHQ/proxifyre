using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;

const uint StunMagicCookie = 0x2112A442;

var options = TestOptions.Parse(args);
var root = FindRepositoryRoot(AppContext.BaseDirectory);
var coreDir = Path.Combine(root, "src", "ProxiFyre", "bin", "Debug", "net10.0-windows", "win-x64");
var coreExe = Path.Combine(coreDir, "ProxiFyre.exe");
var coreAlias = Path.Combine(coreDir, "proxifyre-test-core.exe");
var configPath = Path.Combine(coreDir, "traffic-test-config.json");
var logPath = Path.Combine(coreDir, "proxifyre-core.log");

if (!File.Exists(coreExe))
{
    Console.Error.WriteLine($"Core executable not found: {coreExe}");
    return 1;
}

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

var appPatterns = BuildAppPatterns(options);
var stunEndPoint = options.Kind == TestKind.Stun
    ? await ResolveStunEndPointAsync(options.StunHost, options.StunPort, options.StunAddressFamily, cts.Token)
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
    core = StartProcess(coreAlias, $"--run --config \"{configPath}\"", coreDir, redirect: true);
    coreOutputPump = CaptureProcessOutputAsync(core, coreOutput, options.Detailed, cts.Token);

    await WaitForLogLineAsync(logPath, "Packet filter started.", TimeSpan.FromSeconds(15), cts.Token);
    await Task.Delay(TimeSpan.FromMilliseconds(500), cts.Token);

    var result = options.Kind == TestKind.Curl
        ? await RunCurlTestAsync(options, root, cts.Token)
        : await RunStunTestAsync(options, stunEndPoint!, cts.Token);

    await Task.Delay(TimeSpan.FromSeconds(1), cts.Token);
    var failed = !result.Success;
    PrintLogSummary(logPath, includeRelevantLines: options.Detailed || failed);
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

static async Task<TestResult> RunCurlTestAsync(TestOptions options, string root, CancellationToken cancellationToken)
{
    var curlExe = ResolveCurl();
    var curlArgs = options.CurlArguments ?? throw new InvalidOperationException("curl arguments were not configured.");
    Console.WriteLine($"Test mode: {options.Mode}");
    Console.WriteLine($"Configured app patterns: curl.exe");
    Console.WriteLine($"Running: {curlExe} {curlArgs}");
    using var curl = StartProcess(curlExe, curlArgs, root, redirect: true, clearProxyEnvironment: true);

    var stdout = await curl.StandardOutput.ReadToEndAsync(cancellationToken);
    var stderr = await curl.StandardError.ReadToEndAsync(cancellationToken);
    await curl.WaitForExitAsync(cancellationToken);

    Console.WriteLine("curl stdout:");
    Console.WriteLine(stdout.TrimEnd());
    if (!string.IsNullOrWhiteSpace(stderr))
    {
        Console.WriteLine("curl stderr:");
        Console.WriteLine(stderr.TrimEnd());
    }

    return new TestResult(curl.ExitCode == 0 && stdout.Contains("status=2", StringComparison.Ordinal), stdout, stderr);
}

static async Task<TestResult> RunStunTestAsync(TestOptions options, IPEndPoint stunEndPoint, CancellationToken cancellationToken)
{
    var appPattern = GetCurrentExecutableName();
    Console.WriteLine($"Test mode: {options.Mode}");
    Console.WriteLine($"Configured app patterns: {appPattern}");
    Console.WriteLine($"Running STUN binding request: {appPattern} -> {stunEndPoint}");

    var started = Stopwatch.GetTimestamp();
    var response = await SendStunBindingRequestAsync(stunEndPoint, options.StunAddressFamily, cancellationToken);
    var elapsed = Stopwatch.GetElapsedTime(started);
    if (!response.Success)
    {
        Console.WriteLine($"stun result: failed error={response.Error} time={elapsed.TotalSeconds:F3}s");
        return new TestResult(false, string.Empty, response.Error ?? string.Empty);
    }

    Console.WriteLine($"stun result: success mapped={response.MappedEndPoint} remote={response.RemoteEndPoint} bytes={response.ResponseBytes} time={elapsed.TotalSeconds:F3}s");
    return new TestResult(true, response.MappedEndPoint?.ToString() ?? string.Empty, string.Empty);
}

static string FindRepositoryRoot(string start)
{
    var directory = new DirectoryInfo(start);
    while (directory is not null)
    {
        if (File.Exists(Path.Combine(directory.FullName, "ProxiFyre.sln")))
        {
            return directory.FullName;
        }

        directory = directory.Parent;
    }

    throw new InvalidOperationException("Could not find repository root.");
}

static string ResolveCurl()
{
    var systemCurl = Path.Combine(Environment.SystemDirectory, "curl.exe");
    return File.Exists(systemCurl) ? systemCurl : "curl.exe";
}

static string[] BuildAppPatterns(TestOptions options)
{
    return options.Kind switch
    {
        TestKind.Curl => ["curl.exe"],
        TestKind.Stun => [GetCurrentExecutableName()],
        _ => throw new ArgumentOutOfRangeException(nameof(options))
    };
}

static string GetCurrentExecutableName()
{
    var processPath = Environment.ProcessPath;
    if (!string.IsNullOrWhiteSpace(processPath))
    {
        return Path.GetFileName(processPath);
    }

    using var process = Process.GetCurrentProcess();
    return process.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
        ? process.ProcessName
        : process.ProcessName + ".exe";
}

static async Task<IPEndPoint> ResolveStunEndPointAsync(string host, int port, AddressFamily addressFamily, CancellationToken cancellationToken)
{
    var addresses = await Dns.GetHostAddressesAsync(host, addressFamily, cancellationToken);
    var address = addresses.FirstOrDefault(address => address.AddressFamily == addressFamily)
        ?? throw new InvalidOperationException($"No {addressFamily} address found for STUN host {host}.");
    return new IPEndPoint(address, port);
}

static async Task<StunResult> SendStunBindingRequestAsync(IPEndPoint remoteEndPoint, AddressFamily addressFamily, CancellationToken cancellationToken)
{
    using var socket = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
    socket.Bind(addressFamily == AddressFamily.InterNetwork
        ? new IPEndPoint(IPAddress.Any, 0)
        : new IPEndPoint(IPAddress.IPv6Any, 0));

    var request = CreateStunBindingRequest();
    await socket.SendToAsync(request, SocketFlags.None, remoteEndPoint, cancellationToken);

    var buffer = new byte[1500];
    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
    timeout.CancelAfter(TimeSpan.FromSeconds(8));
    try
    {
        var received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, CreateAnyEndPoint(addressFamily), timeout.Token);
        if (received.RemoteEndPoint is not IPEndPoint responseEndPoint)
        {
            return StunResult.Fail("Response endpoint was not an IP endpoint.");
        }

        if (!TryParseStunBindingResponse(buffer.AsSpan(0, received.ReceivedBytes), request.AsSpan(8, 12), out var mappedEndPoint, out var parseError))
        {
            return StunResult.Fail(parseError);
        }

        return StunResult.Ok(mappedEndPoint, responseEndPoint, received.ReceivedBytes);
    }
    catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
    {
        return StunResult.Fail("Timed out waiting for STUN response.");
    }
}

static EndPoint CreateAnyEndPoint(AddressFamily addressFamily)
{
    return addressFamily == AddressFamily.InterNetwork
        ? new IPEndPoint(IPAddress.Any, 0)
        : new IPEndPoint(IPAddress.IPv6Any, 0);
}

static byte[] CreateStunBindingRequest()
{
    var request = new byte[20];
    BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(0, 2), 0x0001);
    BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2, 2), 0);
    BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(4, 4), StunMagicCookie);
    RandomNumberGenerator.Fill(request.AsSpan(8, 12));
    return request;
}

static bool TryParseStunBindingResponse(ReadOnlySpan<byte> response, ReadOnlySpan<byte> transactionId, out IPEndPoint? mappedEndPoint, out string error)
{
    mappedEndPoint = null;
    error = string.Empty;

    if (response.Length < 20)
    {
        error = $"STUN response too short: {response.Length} bytes.";
        return false;
    }

    var messageType = BinaryPrimitives.ReadUInt16BigEndian(response[..2]);
    if (messageType != 0x0101)
    {
        error = $"Unexpected STUN message type 0x{messageType:X4}.";
        return false;
    }

    var messageLength = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(2, 2));
    if (response.Length < 20 + messageLength)
    {
        error = $"Truncated STUN response: length={response.Length}, declared={messageLength}.";
        return false;
    }

    var magicCookie = BinaryPrimitives.ReadUInt32BigEndian(response.Slice(4, 4));
    if (magicCookie != StunMagicCookie)
    {
        error = $"Unexpected STUN magic cookie 0x{magicCookie:X8}.";
        return false;
    }

    if (!response.Slice(8, 12).SequenceEqual(transactionId))
    {
        error = "STUN transaction ID mismatch.";
        return false;
    }

    var attributes = response.Slice(20, messageLength);
    var offset = 0;
    while (offset + 4 <= attributes.Length)
    {
        var type = BinaryPrimitives.ReadUInt16BigEndian(attributes.Slice(offset, 2));
        var length = BinaryPrimitives.ReadUInt16BigEndian(attributes.Slice(offset + 2, 2));
        offset += 4;
        if (offset + length > attributes.Length)
        {
            error = "Truncated STUN attribute.";
            return false;
        }

        var value = attributes.Slice(offset, length);
        if ((type == 0x0020 && TryParseXorMappedAddress(value, transactionId, out mappedEndPoint))
            || (type == 0x0001 && TryParseMappedAddress(value, out mappedEndPoint)))
        {
            return true;
        }

        offset += Align4(length);
    }

    error = "STUN response did not include MAPPED-ADDRESS or XOR-MAPPED-ADDRESS.";
    return false;
}

static bool TryParseMappedAddress(ReadOnlySpan<byte> value, out IPEndPoint? endPoint)
{
    endPoint = null;
    if (value.Length < 4 || value[0] != 0)
    {
        return false;
    }

    var family = value[1];
    var port = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(2, 2));
    if (family == 0x01 && value.Length >= 8)
    {
        endPoint = new IPEndPoint(new IPAddress(value.Slice(4, 4)), port);
        return true;
    }

    if (family == 0x02 && value.Length >= 20)
    {
        endPoint = new IPEndPoint(new IPAddress(value.Slice(4, 16)), port);
        return true;
    }

    return false;
}

static bool TryParseXorMappedAddress(ReadOnlySpan<byte> value, ReadOnlySpan<byte> transactionId, out IPEndPoint? endPoint)
{
    endPoint = null;
    if (value.Length < 4 || value[0] != 0)
    {
        return false;
    }

    var family = value[1];
    var port = (ushort)(BinaryPrimitives.ReadUInt16BigEndian(value.Slice(2, 2)) ^ (StunMagicCookie >> 16));
    Span<byte> cookieBytes = stackalloc byte[4];
    BinaryPrimitives.WriteUInt32BigEndian(cookieBytes, StunMagicCookie);

    if (family == 0x01 && value.Length >= 8)
    {
        Span<byte> address = stackalloc byte[4];
        value.Slice(4, 4).CopyTo(address);
        for (var i = 0; i < address.Length; i++)
        {
            address[i] ^= cookieBytes[i];
        }

        endPoint = new IPEndPoint(new IPAddress(address), port);
        return true;
    }

    if (family == 0x02 && value.Length >= 20)
    {
        Span<byte> address = stackalloc byte[16];
        value.Slice(4, 16).CopyTo(address);
        for (var i = 0; i < 4; i++)
        {
            address[i] ^= cookieBytes[i];
        }

        for (var i = 0; i < transactionId.Length; i++)
        {
            address[4 + i] ^= transactionId[i];
        }

        endPoint = new IPEndPoint(new IPAddress(address), port);
        return true;
    }

    return false;
}

static int Align4(int value)
{
    return (value + 3) & ~3;
}

static Process StartProcess(string fileName, string arguments, string workingDirectory, bool redirect, bool clearProxyEnvironment = false)
{
    var startInfo = new ProcessStartInfo
    {
        FileName = fileName,
        Arguments = arguments,
        WorkingDirectory = workingDirectory,
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = redirect,
        RedirectStandardError = redirect
    };

    if (clearProxyEnvironment)
    {
        foreach (var key in new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy" })
        {
            startInfo.Environment.Remove(key);
        }
    }

    var process = new Process
    {
        StartInfo = startInfo,
        EnableRaisingEvents = true
    };

    if (!process.Start())
    {
        process.Dispose();
        throw new InvalidOperationException($"Failed to start {fileName}.");
    }

    return process;
}

static Task CaptureProcessOutputAsync(Process process, BoundedLog output, bool echo, CancellationToken cancellationToken)
{
    var stdout = Task.Run(() => CaptureReaderAsync("core>", process.StandardOutput, output, echo, cancellationToken), cancellationToken);
    var stderr = Task.Run(() => CaptureReaderAsync("core!", process.StandardError, output, echo, cancellationToken), cancellationToken);
    return Task.WhenAll(stdout, stderr);
}

static async Task CaptureReaderAsync(string prefix, StreamReader reader, BoundedLog output, bool echo, CancellationToken cancellationToken)
{
    try
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var formatted = $"{prefix} {line}";
            output.Add(formatted);
            if (echo)
            {
                Console.WriteLine(formatted);
            }
        }
    }
    catch (OperationCanceledException)
    {
    }
    catch
    {
    }
}

static async Task WaitForLogLineAsync(string logPath, string text, TimeSpan timeout, CancellationToken cancellationToken)
{
    var deadline = DateTimeOffset.UtcNow + timeout;
    while (DateTimeOffset.UtcNow < deadline)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (File.Exists(logPath) && ReadAllTextShared(logPath).Contains(text, StringComparison.Ordinal))
        {
            return;
        }

        await Task.Delay(200, cancellationToken);
    }

    throw new TimeoutException($"Timed out waiting for log line: {text}");
}

static void PrintLogSummary(string logPath, bool includeRelevantLines)
{
    if (!File.Exists(logPath))
    {
        Console.WriteLine("No core log found.");
        return;
    }

    var lines = ReadAllLinesShared(logPath);
    Console.WriteLine("core log summary:");
    foreach (var pattern in new[]
             {
                 "TCP APP MATCH",
                 "REDIRECT TCP",
                 "PASS RELAY TCP OUT",
                 "PASS RELAY TCP IN",
                 "DIRECT TCP ACCEPT",
                 "DIRECT TCP CONNECT",
                 "DIRECT TCP SEND",
                 "DIRECT TCP RECV",
                 "DIRECT TCP END",
                 "RESTORE TCP RECV",
                 "DIRECT TCP failed",
                 "copy failed",
                 "UDP APP MATCH",
                 "REDIRECT UDP",
                 "DIRECT UDP SEND",
                 "DIRECT UDP RECV",
                 "RESTORE UDP RECV",
                 "DIRECT UDP send failed",
                 "UDP relay remote receive failed",
                 "No direct target",
                 "SendPacket"
             })
    {
        var count = lines.Count(line => line.Contains(pattern, StringComparison.Ordinal));
        Console.WriteLine($"  {pattern}: {count}");
    }

    if (includeRelevantLines)
    {
        Console.WriteLine("last relevant log lines:");
        foreach (var line in lines
                     .Where(IsRelevant)
                     .TakeLast(80))
        {
            Console.WriteLine(line);
        }
    }
}

static string ReadAllTextShared(string path)
{
    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
    using var reader = new StreamReader(stream);
    return reader.ReadToEnd();
}

static string[] ReadAllLinesShared(string path)
{
    return ReadAllTextShared(path)
        .Split(["\r\n", "\n"], StringSplitOptions.None);
}

static bool IsRelevant(string line)
{
    return line.Contains("TCP APP MATCH", StringComparison.Ordinal)
        || line.Contains("REDIRECT TCP", StringComparison.Ordinal)
        || line.Contains("RESTORE TCP", StringComparison.Ordinal)
        || line.Contains("PASS RELAY TCP", StringComparison.Ordinal)
        || line.Contains("DIRECT TCP", StringComparison.Ordinal)
        || line.Contains("UDP APP MATCH", StringComparison.Ordinal)
        || line.Contains("REDIRECT UDP", StringComparison.Ordinal)
        || line.Contains("RESTORE UDP", StringComparison.Ordinal)
        || line.Contains("DIRECT UDP", StringComparison.Ordinal)
        || line.Contains("UDP relay", StringComparison.Ordinal)
        || line.Contains("failed", StringComparison.OrdinalIgnoreCase)
        || line.Contains("No direct target", StringComparison.Ordinal)
        || line.Contains("SendPacket", StringComparison.Ordinal);
}

sealed record TestOptions(
    string Mode,
    TestKind Kind,
    string? CurlArguments,
    bool Detailed,
    string StunHost,
    int StunPort,
    AddressFamily StunAddressFamily)
{
    public static TestOptions Parse(string[] args)
    {
        var mode = "curl-ipv4";
        var detailed = false;

        foreach (var arg in args)
        {
            if (string.Equals(arg, "--verbose", StringComparison.OrdinalIgnoreCase)
                || string.Equals(arg, "--detailed", StringComparison.OrdinalIgnoreCase))
            {
                detailed = true;
                continue;
            }

            if (!arg.StartsWith("-", StringComparison.Ordinal))
            {
                mode = arg;
            }
        }

        var common = "--http1.1 --noproxy \"*\" --proxy \"\" --connect-timeout 8 --max-time 20 -L -sS -o NUL -w \"status=%{http_code} bytes=%{size_download} remote=%{remote_ip} time=%{time_total}\\n\"";
        return mode.ToLowerInvariant() switch
        {
            "curl-ipv4" => new TestOptions(mode, TestKind.Curl, $"--ipv4 {common} https://www.bing.com/", detailed, string.Empty, 0, AddressFamily.Unspecified),
            "curl-ipv6" => new TestOptions(mode, TestKind.Curl, $"--ipv6 {common} https://ipv6.test-ipv6.com/", detailed, string.Empty, 0, AddressFamily.Unspecified),
            "curl-http-ipv4" => new TestOptions(mode, TestKind.Curl, $"--ipv4 {common} http://www.bing.com/", detailed, string.Empty, 0, AddressFamily.Unspecified),
            "stun-ipv4" => new TestOptions(mode, TestKind.Stun, null, detailed, "stun.l.google.com", 19302, AddressFamily.InterNetwork),
            "stun-ipv6" => new TestOptions(mode, TestKind.Stun, null, detailed, "stun.l.google.com", 19302, AddressFamily.InterNetworkV6),
            _ => throw new ArgumentException($"Unknown test mode '{mode}'. Supported modes: curl-ipv4, curl-ipv6, curl-http-ipv4, stun-ipv4, stun-ipv6.")
        };
    }
}

enum TestKind
{
    Curl,
    Stun
}

sealed record TestResult(bool Success, string Stdout, string Stderr);

sealed record StunResult(bool Success, IPEndPoint? MappedEndPoint, IPEndPoint? RemoteEndPoint, int ResponseBytes, string? Error)
{
    public static StunResult Ok(IPEndPoint? mappedEndPoint, IPEndPoint remoteEndPoint, int responseBytes)
    {
        return new StunResult(true, mappedEndPoint, remoteEndPoint, responseBytes, null);
    }

    public static StunResult Fail(string? error)
    {
        return new StunResult(false, null, null, 0, error);
    }
}

sealed class BoundedLog
{
    private readonly int _capacity;
    private readonly Queue<string> _lines = new();
    private readonly object _sync = new();

    public BoundedLog(int capacity)
    {
        _capacity = capacity;
    }

    public void Add(string line)
    {
        lock (_sync)
        {
            _lines.Enqueue(line);
            while (_lines.Count > _capacity)
            {
                _lines.Dequeue();
            }
        }
    }

    public string[] Snapshot()
    {
        lock (_sync)
        {
            return _lines.ToArray();
        }
    }
}
