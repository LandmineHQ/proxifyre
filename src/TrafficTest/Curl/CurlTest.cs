namespace TrafficTest;

internal static class CurlTest
{
    public static async Task<TestResult> RunAsync(TestOptions options, string root, CancellationToken cancellationToken)
    {
        var curlExe = ResolveCurl();
        var curlArgs = options.CurlArguments ?? throw new InvalidOperationException("curl arguments were not configured.");
        Console.WriteLine($"Test mode: {options.Mode}");
        Console.WriteLine("Configured app patterns: curl.exe");
        Console.WriteLine($"Running: {curlExe} {curlArgs}");
        using var curl = ProcessRunner.Start(curlExe, curlArgs, root, redirect: true, clearProxyEnvironment: true);

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

    private static string ResolveCurl()
    {
        var systemCurl = Path.Combine(Environment.SystemDirectory, "curl.exe");
        return File.Exists(systemCurl) ? systemCurl : "curl.exe";
    }
}
