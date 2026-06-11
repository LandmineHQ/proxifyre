using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using Microsoft.Win32;

namespace ProxiFyre;

internal static class WinpkFilterDependency
{
    private const string InstallerFileName = "Windows.Packet.Filter.3.6.2.1.x64.msi";
    private const string DownloadUrl = "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.x64.msi";

    public static async Task EnsureInstalledAsync(Action<string> log, CancellationToken cancellationToken = default)
    {
        var driverInstalled = IsDriverInstalled();
        if (driverInstalled)
        {
            log("WinpkFilter driver dependency check passed.");
            return;
        }

        log("WinpkFilter driver is not installed.");
        var installerPath = await DownloadFileAsync(DownloadUrl, InstallerFileName, log, cancellationToken).ConfigureAwait(false);
        InstallMsi(installerPath, log);

        driverInstalled = IsDriverInstalled();
        if (!driverInstalled)
        {
            throw new InvalidOperationException("WinpkFilter driver installation did not complete cleanly.");
        }

        log("WinpkFilter driver installed.");
    }

    private static async Task<string> DownloadFileAsync(string url, string fileName, Action<string> log, CancellationToken cancellationToken)
    {
        var dependencyDirectory = Path.Combine(AppContext.BaseDirectory, "dependencies");
        Directory.CreateDirectory(dependencyDirectory);

        var filePath = Path.Combine(dependencyDirectory, fileName);
        if (File.Exists(filePath) && new FileInfo(filePath).Length > 1024)
        {
            log($"Using cached dependency: {filePath}");
            return filePath;
        }

        log($"Downloading dependency: {url}");
        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromMinutes(10)
        };

        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var totalBytes = response.Content.Headers.ContentLength;
        var lastLoggedPercent = -1;
        await using var networkStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.Read, 81920, useAsync: true);

        var buffer = new byte[81920];
        long totalRead = 0;
        while (true)
        {
            var read = await networkStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            await fileStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            totalRead += read;

            if (totalBytes is > 0)
            {
                var percent = (int)(totalRead * 100 / totalBytes.Value);
                if (percent >= lastLoggedPercent + 10)
                {
                    lastLoggedPercent = percent;
                    log($"Dependency download progress: {percent}%");
                }
            }
        }

        log($"Downloaded dependency: {filePath}");
        return filePath;
    }

    private static void InstallMsi(string installerPath, Action<string> log)
    {
        log("Installing WinpkFilter driver. A UAC prompt may appear.");
        var installLogPath = Path.Combine(Path.GetDirectoryName(installerPath) ?? AppContext.BaseDirectory, "winpkfilter-msi.log");
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "msiexec.exe",
                Arguments = $"/i \"{installerPath}\" /qn /norestart /L*v \"{installLogPath}\"",
                UseShellExecute = true,
                Verb = "runas"
            }
        };

        try
        {
            process.Start();
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new InvalidOperationException("WinpkFilter installation was cancelled by the user.", ex);
        }

        process.WaitForExit();
        log($"WinpkFilter installer exited with code {process.ExitCode}.");
        log($"WinpkFilter installer log: {installLogPath}");

        if (process.ExitCode is not (0 or 3010))
        {
            throw new InvalidOperationException($"WinpkFilter installer failed with exit code {process.ExitCode}.");
        }
    }

    private static bool IsDriverInstalled()
    {
        try
        {
            using var serviceKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\ndisrd");
            if (serviceKey is not null)
            {
                return true;
            }

            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var softwareKey = baseKey.OpenSubKey(@"SOFTWARE\NT Kernel Resources\WinpkFilter");
            return softwareKey is not null;
        }
        catch
        {
            return false;
        }
    }
}
