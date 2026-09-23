using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Usage", "CA2255", Justification = "NativeAOT module uses a module initializer to start its message loop on load.")]

namespace ProxiFyre;

public static unsafe class ModuleExports
{
    private const int CsHRedraw = 0x0002;
    private const int CsVRedraw = 0x0001;
    private const int HwndMessage = -3;
    private const int WhGetMessage = 3;
    private const int UiHeartbeatTimeoutMs = 10000;
    private const int UiHeartbeatCheckIntervalMs = 2000;
    private const uint CopyDataTimeoutMs = 1000;
    private const uint SmtoAbortIfHung = 0x0002;
    private const uint WmNull = 0x0000;
    private const uint WmClose = 0x0010;
    private const uint WmDestroy = 0x0002;
    private const int CommandRejected = 0;
    private const int CommandAccepted = 1;
    private const int CommandRetryLater = 2;
    private const int CommandAlreadyRunning = 3;

    private static int _initialized;

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int x;
        public int y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public nint hwnd;
        public uint message;
        public nint wParam;
        public nint lParam;
        public uint time;
        public POINT pt;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WNDCLASSEX
    {
        public uint cbSize;
        public uint style;
        public nint lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public nint hInstance;
        public nint hIcon;
        public nint hCursor;
        public nint hbrBackground;
        public char* lpszMenuName;
        public char* lpszClassName;
        public nint hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct COPYDATASTRUCT
    {
        public nint dwData;
        public int cbData;
        public nint lpData;
    }

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern nint GetModuleHandleW(char* lpModuleName);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern ushort RegisterClassExW(WNDCLASSEX* lpWndClass);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern nint CreateWindowExW(
        uint dwExStyle,
        char* lpClassName,
        char* lpWindowName,
        uint dwStyle,
        int x,
        int y,
        int nWidth,
        int nHeight,
        nint hWndParent,
        nint hMenu,
        nint hInstance,
        nint lpParam);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern nint DefWindowProcW(nint hWnd, uint msg, nint wParam, nint lParam);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyWindow(nint hWnd);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindow(nint hWnd);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern uint GetWindowThreadProcessId(nint hWnd, out int processId);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern void PostQuitMessage(int nExitCode);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMessageW(MSG* lpMsg, nint hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TranslateMessage(MSG* lpMsg);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern nint DispatchMessageW(MSG* lpMsg);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostThreadMessageW(uint idThread, uint Msg, nint wParam, nint lParam);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern nint CallNextHookEx(nint hhk, int nCode, nint wParam, nint lParam);

    [UnmanagedCallersOnly(EntryPoint = ModuleMessageProtocol.HookExportName, CallConvs = [typeof(CallConvStdcall)])]
    public static nint GetMsgProc(int code, nint wParam, nint lParam)
    {
        if (code >= 0)
        {
            ModuleRuntime.EnsureStarted();
        }

        return CallNextHookEx(nint.Zero, code, wParam, lParam);
    }

    [System.Runtime.CompilerServices.ModuleInitializer]
    public static void InitializeModule()
    {
        ModuleRuntime.EnsureStarted();
    }

    private static class ModuleRuntime
    {
        private static readonly object Sync = new();
        private static readonly SemaphoreSlim RelayLifecycleGate = new(1, 1);
        private static readonly WndProcDelegate WndProc = WindowProc;
        private static volatile bool RelayStopInProgress;
        private static nint _windowHandle;
        private static uint _windowThreadId;
        private static RelayService? _relayService;
        private static CoreLogger? _logger;
        private static nint _replyHwnd;
        private static int _replyProcessId;
        private static string? _sessionToken;
        private static string? _configPath;
        private static Timer? _heartbeatTimer;
        private static long _lastUiHeartbeatMs;
        private static bool _detailedLogging;
        private static TrafficTelemetryClient? _telemetryClient;

        private delegate nint WndProcDelegate(nint hWnd, uint msg, nint wParam, nint lParam);

        public static void EnsureStarted()
        {
            if (Volatile.Read(ref _initialized) != 0)
            {
                return;
            }

            if (Interlocked.Exchange(ref _initialized, 1) != 0)
            {
                return;
            }

            var thread = new Thread(MessageThreadMain)
            {
                IsBackground = true,
                Name = "ProxiFyre module message loop"
            };
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
        }

        private static void MessageThreadMain()
        {
            try
            {
                _windowThreadId = GetCurrentThreadId();
                _windowHandle = CreateMessageWindow();
                MarkUiHeartbeat();
                _heartbeatTimer = new Timer(CheckUiHeartbeat, null, UiHeartbeatCheckIntervalMs, UiHeartbeatCheckIntervalMs);
                LogLocal("Module message window created.");
                SendEvent("loaded", $"ProxiFyre module loaded in {Process.GetCurrentProcess().ProcessName}.exe pid={Environment.ProcessId}", running: false);

                MSG message;
                while (GetMessageW(&message, nint.Zero, 0, 0))
                {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
            catch (Exception ex)
            {
                LogLocal($"Module message loop failed: {ex}");
                SendEvent("error", $"Module message loop failed: {ex.Message}", running: false);
            }
            finally
            {
                _heartbeatTimer?.Dispose();
                _heartbeatTimer = null;
                StopRelay("Module message loop is exiting.", sendStoppedEvent: false);
                StopTelemetry();
                _logger?.Dispose();
                _logger = null;
            }
        }

        private static nint CreateMessageWindow()
        {
            nint procPtr = Marshal.GetFunctionPointerForDelegate(WndProc);
            fixed (char* className = ModuleMessageProtocol.WindowClassName)
            fixed (char* title = "ProxiFyre Module")
            {
                var wndClass = new WNDCLASSEX
                {
                    cbSize = (uint)sizeof(WNDCLASSEX),
                    style = CsHRedraw | CsVRedraw,
                    lpfnWndProc = procPtr,
                    hInstance = GetModuleHandleW(null),
                    lpszClassName = className
                };

                _ = RegisterClassExW(&wndClass);

                var handle = CreateWindowExW(
                    0,
                    className,
                    title,
                    0,
                    0,
                    0,
                    0,
                    0,
                    new nint(HwndMessage),
                    nint.Zero,
                    wndClass.hInstance,
                    nint.Zero);

                if (handle == nint.Zero)
                {
                    throw new InvalidOperationException($"Failed to create module message window. Win32={Marshal.GetLastWin32Error()}");
                }

                return handle;
            }
        }

        private static nint WindowProc(nint hWnd, uint msg, nint wParam, nint lParam)
        {
            try
            {
                if (msg == ModuleMessageProtocol.WmCopyData)
                {
                    return HandleCopyData(wParam, lParam);
                }

                if (msg == WmClose)
                {
                    StopRelay("Module message window is closing.", sendStoppedEvent: false);
                    DestroyWindow(hWnd);
                    return 0;
                }

                if (msg == WmDestroy)
                {
                    PostQuitMessage(0);
                    return 0;
                }
            }
            catch (Exception ex)
            {
                LogLocal($"WindowProc failed: {ex}");
                SendEvent("error", ex.Message, running: IsRelayRunning());
                return 0;
            }

            return DefWindowProcW(hWnd, msg, wParam, lParam);
        }

        private static nint HandleCopyData(nint senderWindow, nint lParam)
        {
            var copyData = Marshal.PtrToStructure<COPYDATASTRUCT>(lParam);
            if (copyData.dwData != ModuleMessageProtocol.CommandDataId || copyData.cbData <= 2 || copyData.lpData == nint.Zero)
            {
                return CommandRejected;
            }

            var payload = Marshal.PtrToStringUni(copyData.lpData, (copyData.cbData / 2) - 1);
            if (string.IsNullOrWhiteSpace(payload) || !ModuleMessageProtocol.TryParse(payload, out var values))
            {
                return CommandRejected;
            }

            var replyHwnd = ModuleMessageProtocol.GetReplyHwnd(values);
            if (!values.TryGetValue("command", out var command))
            {
                return CommandRejected;
            }

            if (!IsCommandAuthorized(senderWindow, command, values))
            {
                return CommandRejected;
            }

            if (replyHwnd != nint.Zero)
            {
                _replyHwnd = replyHwnd;
                _replyProcessId = GetProcessIdForWindow(senderWindow);
            }

            MarkUiHeartbeat();

            switch (command.ToUpperInvariant())
            {
                case "HEARTBEAT":
                    return CommandAccepted;
                case "PING":
                    SendEvent("status", BuildStatusText(), running: IsRelayRunning());
                    return CommandAccepted;
                case "ATTACH":
                    SendEvent(
                        IsRelayRunning() ? "running" : "stopped",
                        IsRelayRunning()
                            ? $"Relay running in target process pid={Environment.ProcessId}."
                            : "Module attached; relay is stopped.",
                        running: IsRelayRunning(),
                        pid: Environment.ProcessId);
                    return CommandAccepted;
                case "RUN":
                    return RunRelay(values);
                case "RELOAD":
                    return ReloadRelay(values);
                case "STOP":
                    StopRelay("STOP command received.");
                    return CommandAccepted;
                default:
                    SendEvent("error", $"Unknown module command: {command}", running: IsRelayRunning());
                    return CommandRejected;
            }
        }

        private static bool IsCommandAuthorized(
            nint senderWindow,
            string command,
            Dictionary<string, string> values)
        {
            var normalized = command.ToUpperInvariant();
            if (!values.TryGetValue("sessionToken", out var token)
                || string.IsNullOrWhiteSpace(token))
            {
                return false;
            }

            if (string.IsNullOrEmpty(_sessionToken))
            {
                if (normalized is not ("ATTACH" or "RUN")
                    || !IsTrustedBootstrapSender(senderWindow))
                {
                    return false;
                }

                _sessionToken = token;
                return true;
            }

            if (token.Equals(_sessionToken, StringComparison.Ordinal))
            {
                return true;
            }

            if (normalized is ("ATTACH" or "RUN")
                && senderWindow != nint.Zero
                && IsTrustedBootstrapSender(senderWindow)
                && !IsReplySessionAlive())
            {
                _sessionToken = token;
                return true;
            }

            return false;
        }

        private static bool IsTrustedBootstrapSender(nint senderWindow)
        {
            try
            {
                var processId = GetProcessIdForWindow(senderWindow);
                if (processId <= 0)
                {
                    return false;
                }

                using var process = Process.GetProcessById(processId);
                var processName = process.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? process.ProcessName
                    : process.ProcessName + ".exe";
                if (!processName.Equals("ProxiFyre.exe", StringComparison.OrdinalIgnoreCase)
                    && !processName.Equals("TrafficTest.exe", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                try
                {
                    return process.SessionId == Process.GetCurrentProcess().SessionId;
                }
                catch
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        private static int GetProcessIdForWindow(nint window)
        {
            return window != nint.Zero
                && GetWindowThreadProcessId(window, out var processId) != 0
                ? processId
                : 0;
        }

        private static bool IsReplySessionAlive()
        {
            if (_replyHwnd == nint.Zero || !IsWindow(_replyHwnd))
            {
                return false;
            }

            if (_replyProcessId <= 0)
            {
                return true;
            }

            try
            {
                using var process = Process.GetProcessById(_replyProcessId);
                if (process.HasExited)
                {
                    return false;
                }

                try
                {
                    return process.SessionId == Process.GetCurrentProcess().SessionId;
                }
                catch
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        private static int RunRelay(Dictionary<string, string> values)
        {
            var configPath = RequireValue(values, "configPath");
            _configPath = configPath;
            _detailedLogging = ModuleMessageProtocol.GetBool(values, "detailed");
            values.TryGetValue("telemetryPipeName", out var telemetryPipeName);
            values.TryGetValue("nativeDirectory", out var nativeDirectory);
            var networkHandle = ModuleMessageProtocol.GetHandle(values, "networkHandle");
            var flowHandle = ModuleMessageProtocol.GetHandle(values, "flowHandle");

            if (values.TryGetValue("logPath", out var logPath) && !string.IsNullOrWhiteSpace(logPath))
            {
                Environment.SetEnvironmentVariable("PROXIFYRE_MODULE_LOG", logPath);
            }

            RelayLifecycleGate.Wait();
            try
            {
                if (RelayStopInProgress)
                {
                    SendEvent("error", "Relay is still stopping; retry RUN.", running: false);
                    return CommandRetryLater;
                }

                lock (Sync)
                {
                    EnsureLogger(logPath);

                    var configuration = NormalizeForCurrentProcess(AppConfiguration.Load(configPath));
                    if (_relayService is { IsRunning: true } relay)
                    {
                        relay.Reload(configuration);
                        SendEvent("running", "Relay was already running; configuration reloaded.", running: true);
                        return CommandAlreadyRunning;
                    }

                    var previousRelay = _relayService;
                    _relayService = null;
                    previousRelay?.Dispose();

                    StopTelemetry();
                    if (!string.IsNullOrWhiteSpace(telemetryPipeName))
                    {
                        _telemetryClient = new TrafficTelemetryClient(telemetryPipeName, LogLocal);
                        _telemetryClient.Start();
                    }

                    Action<TrafficSnapshot>? trafficSink = _telemetryClient is null ? null : _telemetryClient.TryPublish;
                    _relayService = new RelayService(
                        LogRelay,
                        _detailedLogging,
                        trafficSink,
                        warningLog: LogWarning);
                    _relayService.Start(
                        configuration,
                        configPath,
                        nativeDirectory: nativeDirectory,
                        networkHandle: networkHandle,
                        flowHandle: flowHandle);
                }
            }
            finally
            {
                RelayLifecycleGate.Release();
            }

            SendEvent("running", $"Relay running in target process pid={Environment.ProcessId}.", running: true, pid: Environment.ProcessId);
            return CommandAccepted;
        }

        private static int ReloadRelay(Dictionary<string, string> values)
        {
            var configPath = values.TryGetValue("configPath", out var path) && !string.IsNullOrWhiteSpace(path)
                ? path
                : _configPath;

            if (string.IsNullOrWhiteSpace(configPath))
            {
                SendEvent("error", "Cannot reload because configPath is unknown.", running: IsRelayRunning());
                return CommandRejected;
            }

            RelayLifecycleGate.Wait();
            try
            {
                if (RelayStopInProgress)
                {
                    SendEvent("error", "Relay is still stopping; retry RELOAD.", running: false);
                    return CommandRetryLater;
                }

                var configuration = NormalizeForCurrentProcess(AppConfiguration.Load(configPath));
                lock (Sync)
                {
                    if (_relayService is not { IsRunning: true } relay)
                    {
                        SendEvent("stopped", "Configuration loaded, but relay is not running.", running: false);
                        return CommandRejected;
                    }

                    relay.Reload(configuration);
                }
            }
            finally
            {
                RelayLifecycleGate.Release();
            }

            SendEvent("reloaded", $"Configuration reloaded from {configPath}.", running: true);
            return CommandAccepted;
        }

        private static void StopRelay(string reason, bool sendStoppedEvent = true)
        {
            RelayLifecycleGate.Wait();
            RelayService? relay;
            lock (Sync)
            {
                relay = _relayService;
                _relayService = null;
            }

            RelayStopInProgress = relay is not null || RelayStopInProgress;
            StopTelemetry();

            if (relay is null)
            {
                if (sendStoppedEvent)
                {
                    SendEvent("stopped", "Relay is already stopped. AOT module remains loaded.", running: false);
                }

                RelayLifecycleGate.Release();
                return;
            }

            QueueRelayStop(relay, reason, sendStoppedEvent);
        }

        private static void QueueRelayStop(RelayService relay, string reason, bool sendStoppedEvent)
        {
            _ = Task.Run(() =>
            {
                try
                {
                    LogLocal($"Stopping relay asynchronously: {reason}");
                    relay.Dispose();
                    LogLocal("Relay stop completed.");
                    if (sendStoppedEvent)
                    {
                        SendEvent("stopped", "Relay stopped. AOT module remains loaded until the target process exits.", running: false);
                    }
                }
                catch (Exception ex)
                {
                    LogLocal($"Stop failed: {ex}");
                    SendEvent("error", $"Stop failed: {ex.Message}", running: false);
                }
                finally
                {
                    RelayStopInProgress = false;
                    RelayLifecycleGate.Release();
                }
            });
        }

        private static void StopTelemetry()
        {
            TrafficTelemetryClient? client;
            lock (Sync)
            {
                client = _telemetryClient;
                _telemetryClient = null;
            }

            client?.Dispose();
        }

        private static void MarkUiHeartbeat()
        {
            Interlocked.Exchange(ref _lastUiHeartbeatMs, Environment.TickCount64);
        }

        private static void CheckUiHeartbeat(object? state)
        {
            try
            {
                if (!IsRelayRunning())
                {
                    return;
                }

                var lastHeartbeat = Interlocked.Read(ref _lastUiHeartbeatMs);
                if (lastHeartbeat <= 0)
                {
                    return;
                }

                var elapsedMs = Environment.TickCount64 - lastHeartbeat;
                if (elapsedMs <= UiHeartbeatTimeoutMs)
                {
                    return;
                }

                LogLocal($"UI heartbeat lost for {elapsedMs} ms; stopping relay.");
                StopRelay("UI heartbeat lost.");
            }
            catch (Exception ex)
            {
                LogLocal($"UI heartbeat check failed: {ex}");
            }
        }

        private static bool IsRelayRunning()
        {
            lock (Sync)
            {
                return _relayService is { IsRunning: true };
            }
        }

        private static string BuildStatusText()
        {
            return IsRelayRunning()
                ? $"Relay running in pid={Environment.ProcessId}."
                : $"Module loaded in pid={Environment.ProcessId}; relay is stopped.";
        }

        private static string RequireValue(Dictionary<string, string> values, string key)
        {
            if (!values.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException($"{key} is required.");
            }

            return value;
        }

        private static AppConfiguration NormalizeForCurrentProcess(AppConfiguration configuration)
        {
            var processName = Process.GetCurrentProcess().ProcessName;
            if (!processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                processName += ".exe";
            }

            return new AppConfiguration
            {
                CoreProcessName = processName,
                LicenseKey = configuration.LicenseKey,
                ModuleDllName = configuration.ModuleDllName,
                EnableFakeIpWhitelist = configuration.EnableFakeIpWhitelist,
                Detailed = configuration.Detailed,
                Apps = configuration.Apps
            };
        }

        private static void EnsureLogger(string? requestedLogPath = null)
        {
            if (!string.IsNullOrWhiteSpace(requestedLogPath)
                && (_logger is null || !string.Equals(_logger.LogPath, requestedLogPath, StringComparison.OrdinalIgnoreCase)))
            {
                _logger?.Dispose();
                _logger = CoreLogger.Create(requestedLogPath);
                return;
            }

            _logger ??= CreateLogger();
        }

        private static CoreLogger CreateLogger()
        {
            var requestedLogPath = Environment.GetEnvironmentVariable("PROXIFYRE_MODULE_LOG");
            if (string.IsNullOrWhiteSpace(requestedLogPath))
            {
                return CoreLogger.CreateForCurrentProcess();
            }

            return CoreLogger.Create(requestedLogPath);
        }

        private static void LogRelay(string message)
        {
            EnsureLogger();
            _logger?.Info(message);
            SendEvent("log", message, running: IsRelayRunning());
        }

        private static void LogWarning(string message)
        {
            EnsureLogger();
            _logger?.Warning(message);
            SendEvent("warning", message, running: IsRelayRunning());
        }

        private static void LogLocal(string message)
        {
            try
            {
                _logger?.Info(message);
            }
            catch
            {
            }
        }

        private static void SendEvent(string eventName, string text, bool? running = null, int? pid = null)
        {
            var target = _replyHwnd;
            if (target == nint.Zero)
            {
                return;
            }

            var payload = ModuleMessageProtocol.BuildEvent(
                eventName,
                text,
                running,
                pid,
                _sessionToken);
            SendCopyData(target, ModuleMessageProtocol.EventDataId, payload);
        }

        private static void SendCopyData(nint targetWindow, int dataId, string payload)
        {
            var bytes = Encoding.Unicode.GetBytes(payload + '\0');
            fixed (byte* bytesPtr = bytes)
            {
                var copyData = new COPYDATASTRUCT
                {
                    dwData = dataId,
                    cbData = bytes.Length,
                    lpData = (nint)bytesPtr
                };

                _ = NativeCopyData.SendMessageTimeoutW(
                    targetWindow,
                    ModuleMessageProtocol.WmCopyData,
                    _windowHandle,
                    (nint)(&copyData),
                    SmtoAbortIfHung,
                    CopyDataTimeoutMs,
                    out _);
            }
        }

        public static void WakeMessageLoop()
        {
            var threadId = _windowThreadId;
            if (threadId != 0)
            {
                PostThreadMessageW(threadId, WmNull, nint.Zero, nint.Zero);
            }
        }
    }

    private static class NativeCopyData
    {
        [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern nint SendMessageTimeoutW(
            nint hWnd,
            uint msg,
            nint wParam,
            nint lParam,
            uint fuFlags,
            uint uTimeout,
            out nint lpdwResult);
    }
}
