using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Threading;

namespace ProxiFyre;

internal sealed class UiSingleInstanceCoordinator : IDisposable
{
    private const string MutexName = @"Local\ProxiFyre.Ui.SingleInstance";
    private const string ActivationEventName = @"Local\ProxiFyre.Ui.Activate";
    private const string MainWindowTitle = "ProxiFyre Direct Relay";
    private const int SwRestore = 9;

    private readonly Mutex _mutex;
    private readonly EventWaitHandle _activationEvent;
    private readonly CancellationTokenSource _cancellationTokenSource = new();
    private Task? _listenerTask;
    private bool _disposed;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern nint FindWindowW(string? lpClassName, string? lpWindowName);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(nint hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(nint hWnd, int nCmdShow);

    private UiSingleInstanceCoordinator(Mutex mutex, EventWaitHandle activationEvent)
    {
        _mutex = mutex;
        _activationEvent = activationEvent;
    }

    public static bool TryAcquirePrimary([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out UiSingleInstanceCoordinator? coordinator)
    {
        return TryAcquirePrimary(TimeSpan.Zero, out coordinator);
    }

    public static bool TryAcquirePrimary(
        TimeSpan retryTimeout,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out UiSingleInstanceCoordinator? coordinator)
    {
        coordinator = null;

        var activationEvent = new EventWaitHandle(
            initialState: false,
            EventResetMode.AutoReset,
            ActivationEventName);
        var mutex = new Mutex(initiallyOwned: false, MutexName);
        var ownsMutex = false;

        try
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            while (true)
            {
                try
                {
                    var remaining = retryTimeout - stopwatch.Elapsed;
                    var waitMilliseconds = retryTimeout <= TimeSpan.Zero
                        ? 0
                        : (int)Math.Clamp(remaining.TotalMilliseconds, 0, 250);
                    ownsMutex = mutex.WaitOne(waitMilliseconds);
                }
                catch (AbandonedMutexException)
                {
                    ownsMutex = true;
                }

                if (ownsMutex || retryTimeout <= TimeSpan.Zero || stopwatch.Elapsed >= retryTimeout)
                {
                    break;
                }
            }

            if (!ownsMutex)
            {
                activationEvent.Set();
                TryActivateExistingWindow();
                activationEvent.Dispose();
                mutex.Dispose();
                return false;
            }

            coordinator = new UiSingleInstanceCoordinator(mutex, activationEvent);
            return true;
        }
        catch
        {
            if (ownsMutex)
            {
                mutex.ReleaseMutex();
            }

            activationEvent.Dispose();
            mutex.Dispose();
            throw;
        }
    }

    public void StartListening(Dispatcher dispatcher, Action activateWindow)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _listenerTask = Task.Run(() =>
        {
            var waitHandles = new WaitHandle[]
            {
                _activationEvent,
                _cancellationTokenSource.Token.WaitHandle
            };

            while (!_cancellationTokenSource.IsCancellationRequested)
            {
                var signaled = WaitHandle.WaitAny(waitHandles);
                if (signaled != 0 || _cancellationTokenSource.IsCancellationRequested)
                {
                    break;
                }

                dispatcher.BeginInvoke(activateWindow);
            }
        });
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cancellationTokenSource.Cancel();

        try
        {
            _listenerTask?.Wait(TimeSpan.FromSeconds(1));
        }
        catch
        {
        }

        _cancellationTokenSource.Dispose();
        _activationEvent.Dispose();
        _mutex.ReleaseMutex();
        _mutex.Dispose();
    }

    private static void TryActivateExistingWindow()
    {
        var window = FindWindowW(null, MainWindowTitle);
        if (window == nint.Zero)
        {
            return;
        }

        ShowWindow(window, SwRestore);
        SetForegroundWindow(window);
    }
}
