using System.Diagnostics;
using System.IO;

namespace ProxiFyre;

internal sealed class CoreProcessHost : IDisposable, IAsyncDisposable
{
    private readonly Action<string> _log;
    private readonly Action _onExited;
    private Process? _process;

    public CoreProcessHost(Action<string> log, Action onExited)
    {
        _log = log;
        _onExited = onExited;
    }

    public bool IsRunning => _process is { HasExited: false };

    public void Start(string configPath, string coreProcessName)
    {
        if (IsRunning)
        {
            return;
        }

        var corePath = PrepareCoreExecutable(coreProcessName);
        _log($"Starting core: {Path.GetFileName(corePath)}");
        _log($"Relay network activity will appear under process: {Path.GetFileName(corePath)}");
        _log($"Core detailed log: {Path.Combine(AppContext.BaseDirectory, "proxifyre-core.log")}");

        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = corePath,
                WorkingDirectory = AppContext.BaseDirectory,
                Arguments = $"--run --config \"{Path.GetFullPath(configPath)}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            },
            EnableRaisingEvents = true
        };

        process.OutputDataReceived += OnOutputDataReceived;
        process.ErrorDataReceived += OnOutputDataReceived;
        process.Exited += OnProcessExited;

        if (!process.Start())
        {
            process.Dispose();
            throw new InvalidOperationException("Failed to start core process.");
        }

        _process = process;
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
    }

    public async Task StopAsync()
    {
        var process = _process;
        if (process is null)
        {
            return;
        }

        process.Exited -= OnProcessExited;
        process.OutputDataReceived -= OnOutputDataReceived;
        process.ErrorDataReceived -= OnOutputDataReceived;

        try
        {
            if (!process.HasExited)
            {
                _log("Stopping core process...");
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3));
            }
        }
        catch (Exception ex)
        {
            _log($"Failed to stop core process cleanly: {ex.Message}");
        }
        finally
        {
            process.Dispose();
            if (ReferenceEquals(_process, process))
            {
                _process = null;
            }
        }
    }

    private static string PrepareCoreExecutable(string coreProcessName)
    {
        var normalizedName = AppConfiguration.NormalizeCoreProcessName(coreProcessName);
        var sourcePath = Path.Combine(AppContext.BaseDirectory, "ProxiFyre.exe");
        if (!File.Exists(sourcePath))
        {
            throw new FileNotFoundException("Built core executable was not found.", sourcePath);
        }

        var targetPath = Path.Combine(AppContext.BaseDirectory, normalizedName);
        if (string.Equals(sourcePath, targetPath, StringComparison.OrdinalIgnoreCase))
        {
            return sourcePath;
        }

        var sourceInfo = new FileInfo(sourcePath);
        var targetInfo = new FileInfo(targetPath);
        if (!targetInfo.Exists || targetInfo.Length != sourceInfo.Length || targetInfo.LastWriteTimeUtc < sourceInfo.LastWriteTimeUtc)
        {
            File.Copy(sourcePath, targetPath, overwrite: true);
            File.SetLastWriteTimeUtc(targetPath, sourceInfo.LastWriteTimeUtc);
        }

        return targetPath;
    }

    private void OnOutputDataReceived(object sender, DataReceivedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(e.Data))
        {
            _log(e.Data);
        }
    }

    private void OnProcessExited(object? sender, EventArgs e)
    {
        if (sender is Process process)
        {
            process.OutputDataReceived -= OnOutputDataReceived;
            process.ErrorDataReceived -= OnOutputDataReceived;
            process.Exited -= OnProcessExited;
            process.Dispose();

            if (ReferenceEquals(_process, process))
            {
                _process = null;
            }
        }

        _log("Core process stopped.");
        _onExited();
    }

    public void Dispose()
    {
        StopAsync().GetAwaiter().GetResult();
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
    }
}
