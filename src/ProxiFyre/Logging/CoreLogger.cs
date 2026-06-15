using System.Diagnostics;
using System.IO;

namespace ProxiFyre;

internal sealed class CoreLogger : IDisposable
{
    private readonly object _sync = new();
    private readonly StreamWriter _writer;
    private bool _disposed;

    private CoreLogger(string logPath)
    {
        LogPath = logPath;
        Directory.CreateDirectory(Path.GetDirectoryName(logPath) ?? AppContext.BaseDirectory);
        _writer = new StreamWriter(new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
        {
            AutoFlush = true
        };
    }

    public string LogPath { get; }

    public static CoreLogger CreateForCurrentProcess()
    {
        var logPath = Path.Combine(AppContext.BaseDirectory, "proxifyre-core.log");
        var logger = Create(logPath);
        logger.Info("============================================================");
        logger.Info("Core log session started.");
        logger.Info($"Process: {Process.GetCurrentProcess().ProcessName} pid={Environment.ProcessId}");
        logger.Info($"Process path: {Environment.ProcessPath}");
        logger.Info($"Base directory: {AppContext.BaseDirectory}");
        logger.Info($"Log file: {logPath}");
        return logger;
    }

    public static CoreLogger Create(string logPath)
    {
        return new CoreLogger(logPath);
    }

    public void Info(string message) => Write("INFO", message, Console.Out);

    public void Error(string message) => Write("ERROR", message, Console.Error);

    private void Write(string level, string message, TextWriter console)
    {
        var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} [{level}] {message}";
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _writer.WriteLine(line);
        }

        console.WriteLine(line);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _writer.WriteLine($"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} [INFO] Core log session ended.");
            _writer.Dispose();
            _disposed = true;
        }
    }
}
