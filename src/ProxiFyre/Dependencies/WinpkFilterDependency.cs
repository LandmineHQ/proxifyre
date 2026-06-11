using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ProxiFyre;

internal static class WinpkFilterDependency
{
    private const string NdisApiDllName = "ndisapi.dll";
    private const string InstallerFileName = "Windows.Packet.Filter.3.6.2.1.x64.msi";
    private const string DownloadUrl = "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.x64.msi";

    public static async Task EnsureInstalledAsync(Action<string> log, CancellationToken cancellationToken = default)
    {
        var dllLoadable = IsNdisApiDllLoadable();
        var driverInstalled = IsDriverInstalled();
        if (dllLoadable && driverInstalled)
        {
            log("WinpkFilter dependency check passed.");
            return;
        }

        log($"WinpkFilter dependency missing: dllLoadable={dllLoadable}, driverInstalled={driverInstalled}");
        var installerPath = await DownloadInstallerAsync(log, cancellationToken).ConfigureAwait(false);
        InstallMsi(installerPath, log);

        dllLoadable = IsNdisApiDllLoadable();
        driverInstalled = IsDriverInstalled();
        if (!dllLoadable || !driverInstalled)
        {
            throw new InvalidOperationException($"WinpkFilter installation did not complete cleanly. dllLoadable={dllLoadable}, driverInstalled={driverInstalled}");
        }

        log("WinpkFilter dependency installed.");
    }

    private static async Task<string> DownloadInstallerAsync(Action<string> log, CancellationToken cancellationToken)
    {
        var dependencyDirectory = Path.Combine(AppContext.BaseDirectory, "dependencies");
        Directory.CreateDirectory(dependencyDirectory);

        var installerPath = Path.Combine(dependencyDirectory, InstallerFileName);
        if (File.Exists(installerPath) && new FileInfo(installerPath).Length > 1024 * 1024)
        {
            log($"Using cached WinpkFilter installer: {installerPath}");
            return installerPath;
        }

        log($"Downloading WinpkFilter installer: {DownloadUrl}");
        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromMinutes(10)
        };

        using var response = await client.GetAsync(DownloadUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var totalBytes = response.Content.Headers.ContentLength;
        var lastLoggedPercent = -1;
        await using var networkStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var fileStream = new FileStream(installerPath, FileMode.Create, FileAccess.Write, FileShare.Read, 81920, useAsync: true);

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
                    log($"WinpkFilter download progress: {percent}%");
                }
            }
        }

        log($"Downloaded WinpkFilter installer: {installerPath}");
        return installerPath;
    }

    private static void InstallMsi(string installerPath, Action<string> log)
    {
        log("Installing WinpkFilter driver. A UAC prompt may appear.");
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "msiexec.exe",
                Arguments = $"/i \"{installerPath}\" /qn /norestart",
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

        if (process.ExitCode is not (0 or 3010))
        {
            throw new InvalidOperationException($"WinpkFilter installer failed with exit code {process.ExitCode}.");
        }
    }

    private static bool IsNdisApiDllLoadable()
    {
        var localPath = Path.Combine(AppContext.BaseDirectory, NdisApiDllName);
        if (File.Exists(localPath) && TryLoad(localPath))
        {
            return true;
        }

        return TryLoad(NdisApiDllName);
    }

    private static bool TryLoad(string path)
    {
        if (!NativeLibrary.TryLoad(path, out var handle))
        {
            return false;
        }

        NativeLibrary.Free(handle);
        return true;
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
