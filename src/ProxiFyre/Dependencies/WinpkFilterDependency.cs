using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace ProxiFyre;

internal static class WinpkFilterDependency
{
    private const string InstallerFileName = "Windows.Packet.Filter.3.6.2.1.x64.msi";
    private const string DownloadUrl = "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.x64.msi";
    private const string GhProxyPrefix = "https://ghproxy.net/";
    private static readonly Regex ProductCodePattern = new(@"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static WinpkFilterStatus GetStatus()
    {
        var serviceInstalled = HasServiceKey();
        var softwareInstalled = HasSoftwareKey();
        var product = FindInstalledProduct();
        var installed = serviceInstalled || softwareInstalled || product is not null;

        if (!installed)
        {
            return new WinpkFilterStatus(false, "未安装", "未检测到 ndisrd 服务或 WinpkFilter 安装记录。", null);
        }

        var detailParts = new List<string>();
        if (serviceInstalled)
        {
            detailParts.Add("ndisrd 服务已存在");
        }

        if (softwareInstalled)
        {
            detailParts.Add("WinpkFilter 注册表项已存在");
        }

        if (product is not null)
        {
            var productText = string.IsNullOrWhiteSpace(product.DisplayVersion)
                ? product.DisplayName
                : $"{product.DisplayName} {product.DisplayVersion}";
            detailParts.Add($"MSI: {productText}");
        }

        return new WinpkFilterStatus(true, "已安装", string.Join("；", detailParts), product?.ProductCode);
    }

    public static async Task EnsureInstalledAsync(Action<string> log, CancellationToken cancellationToken = default)
    {
        var driverInstalled = GetStatus().IsInstalled;
        if (driverInstalled)
        {
            log("WinpkFilter driver dependency check passed.");
            return;
        }

        log("WinpkFilter driver is not installed.");
        var installerPath = await DownloadFileAsync(DownloadUrl, InstallerFileName, log, cancellationToken).ConfigureAwait(false);
        await InstallMsiAsync(installerPath, log, cancellationToken).ConfigureAwait(false);

        driverInstalled = GetStatus().IsInstalled;
        if (!driverInstalled)
        {
            throw new InvalidOperationException("WinpkFilter driver installation did not complete cleanly.");
        }

        log("WinpkFilter driver installed.");
    }

    public static async Task UninstallAsync(Action<string> log, CancellationToken cancellationToken = default)
    {
        var status = GetStatus();
        if (!status.IsInstalled)
        {
            log("WinpkFilter driver is not installed.");
            return;
        }

        if (string.IsNullOrWhiteSpace(status.ProductCode))
        {
            throw new InvalidOperationException("Could not locate the WinpkFilter MSI product code. Please uninstall it from Windows Apps & Features.");
        }

        await UninstallMsiAsync(status.ProductCode, log, cancellationToken).ConfigureAwait(false);

        if (GetStatus().IsInstalled)
        {
            log("WinpkFilter uninstall finished, but registry/service records are still present. A reboot may be required.");
            return;
        }

        log("WinpkFilter driver uninstalled.");
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

        var urls = new[] { url, GhProxyPrefix + url };
        Exception? lastError = null;
        for (var i = 0; i < urls.Length; i++)
        {
            var candidateUrl = urls[i];
            var sourceName = i == 0 ? "GitHub" : "ghproxy";
            try
            {
                await DownloadFileFromUrlAsync(candidateUrl, filePath, sourceName, log, cancellationToken).ConfigureAwait(false);
                log($"Downloaded dependency: {filePath}");
                return filePath;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException
                || (ex is TaskCanceledException && !cancellationToken.IsCancellationRequested))
            {
                lastError = ex;
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }

                log($"{sourceName} dependency download failed: {ex.Message}");
                if (i + 1 < urls.Length)
                {
                    log("Retrying dependency download through ghproxy.");
                }
            }
        }

        throw new InvalidOperationException("Could not download WinpkFilter dependency.", lastError);
    }

    private static async Task DownloadFileFromUrlAsync(
        string url,
        string filePath,
        string sourceName,
        Action<string> log,
        CancellationToken cancellationToken)
    {
        log($"Downloading dependency from {sourceName}: {url}");
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
                    log($"Dependency download progress ({sourceName}): {percent}%");
                }
            }
        }
    }

    private static async Task InstallMsiAsync(string installerPath, Action<string> log, CancellationToken cancellationToken)
    {
        log("Installing WinpkFilter driver. A UAC prompt may appear.");
        var installLogPath = Path.Combine(Path.GetDirectoryName(installerPath) ?? AppContext.BaseDirectory, "winpkfilter-msi.log");
        using var process = StartElevatedMsiexec($"/i \"{installerPath}\" /qn /norestart /L*v \"{installLogPath}\"", "WinpkFilter installation was cancelled by the user.");
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        log($"WinpkFilter installer exited with code {process.ExitCode}.");
        log($"WinpkFilter installer log: {installLogPath}");

        if (process.ExitCode is not (0 or 3010))
        {
            throw new InvalidOperationException($"WinpkFilter installer failed with exit code {process.ExitCode}.");
        }
    }

    private static async Task UninstallMsiAsync(string productCode, Action<string> log, CancellationToken cancellationToken)
    {
        log("Uninstalling WinpkFilter driver. A UAC prompt may appear.");
        var uninstallLogPath = Path.Combine(AppContext.BaseDirectory, "dependencies", "winpkfilter-uninstall-msi.log");
        Directory.CreateDirectory(Path.GetDirectoryName(uninstallLogPath) ?? AppContext.BaseDirectory);
        using var process = StartElevatedMsiexec($"/x \"{productCode}\" /qn /norestart /L*v \"{uninstallLogPath}\"", "WinpkFilter uninstallation was cancelled by the user.");
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        log($"WinpkFilter uninstaller exited with code {process.ExitCode}.");
        log($"WinpkFilter uninstaller log: {uninstallLogPath}");

        if (process.ExitCode is not (0 or 3010))
        {
            throw new InvalidOperationException($"WinpkFilter uninstaller failed with exit code {process.ExitCode}.");
        }
    }

    private static Process StartElevatedMsiexec(string arguments, string cancellationMessage)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "msiexec.exe",
                Arguments = arguments,
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
            throw new InvalidOperationException(cancellationMessage, ex);
        }

        return process;
    }

    private static bool HasServiceKey()
    {
        try
        {
            using var serviceKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\ndisrd");
            return serviceKey is not null;
        }
        catch
        {
            return false;
        }
    }

    private static bool HasSoftwareKey()
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var softwareKey = baseKey.OpenSubKey(@"SOFTWARE\NT Kernel Resources\WinpkFilter");
            return softwareKey is not null;
        }
        catch
        {
            return false;
        }
    }

    private static WinpkFilterProduct? FindInstalledProduct()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var uninstallKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (uninstallKey is null)
                {
                    continue;
                }

                foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                {
                    using var productKey = uninstallKey.OpenSubKey(subKeyName);
                    var displayName = productKey?.GetValue("DisplayName") as string;
                    if (!IsWinpkFilterProduct(displayName))
                    {
                        continue;
                    }

                    var displayVersion = productKey?.GetValue("DisplayVersion") as string;
                    var uninstallString = productKey?.GetValue("QuietUninstallString") as string
                        ?? productKey?.GetValue("UninstallString") as string;
                    var productCode = TryExtractProductCode(subKeyName) ?? TryExtractProductCode(uninstallString);
                    return new WinpkFilterProduct(displayName!, displayVersion, productCode);
                }
            }
            catch
            {
                continue;
            }
        }

        return null;
    }

    private static bool IsWinpkFilterProduct(string? displayName)
    {
        return !string.IsNullOrWhiteSpace(displayName)
            && (displayName.Contains("WinpkFilter", StringComparison.OrdinalIgnoreCase)
                || displayName.Contains("Windows Packet Filter", StringComparison.OrdinalIgnoreCase));
    }

    private static string? TryExtractProductCode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var match = ProductCodePattern.Match(value);
        return match.Success ? match.Value : null;
    }

    private sealed record WinpkFilterProduct(string DisplayName, string? DisplayVersion, string? ProductCode);
}

public sealed record WinpkFilterStatus(bool IsInstalled, string StatusText, string Detail, string? ProductCode);
