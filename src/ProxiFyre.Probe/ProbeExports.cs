using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;

namespace ProxiFyre;

public static unsafe class ProbeExports
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

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeWindowMessageFilter(uint message, uint dwFlag);

    private const uint MsgfltAdd = 1;

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyWindow(nint hWnd);

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
            ProbeRuntime.EnsureStarted();
        }

        return CallNextHookEx(nint.Zero, code, wParam, lParam);
    }

    [System.Runtime.CompilerServices.ModuleInitializer]
    public static void InitializeModule()
    {
        ProbeRuntime.EnsureStarted();
    }

    // ------------------ HOOKING LOGIC ------------------

    private static Hook? _deviceIoControlHook;
    private static Hook? _filterSendMessageHook;

    private static readonly object LogLock = new object();
    private const string LogFilePath = @"C:\Users\z1216\Desktop\proxifyre\leigod-probe.log";

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", EntryPoint = "GetModuleHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandleWString(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryW(string lpLibFileName);

    [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OriginalDeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("fltlib.dll", EntryPoint = "FilterSendMessage", SetLastError = true)]
    private static extern int OriginalFilterSendMessage(
        IntPtr hPort,
        IntPtr lpInBuffer,
        uint dwInBufferSize,
        IntPtr lpOutBuffer,
        uint dwOutBufferSize,
        out uint lpBytesReturned);

    private class Hook
    {
        private readonly byte[] _originalBytes;
        private readonly byte[] _hookBytes;
        private readonly IntPtr _targetAddress;
        private readonly int _patchSize;
        public object Lock { get; } = new();

        public Hook(IntPtr targetAddress, IntPtr detourAddress)
        {
            _targetAddress = targetAddress;

            if (IntPtr.Size == 4)
            {
                // x86: 5-byte relative JMP (E9 rel32)
                _patchSize = 5;
                _hookBytes = new byte[5];
                _hookBytes[0] = 0xE9; // JMP rel32
                int relativeOffset = (int)((long)detourAddress - (long)targetAddress - 5);
                var relBytes = BitConverter.GetBytes(relativeOffset);
                Array.Copy(relBytes, 0, _hookBytes, 1, 4);
            }
            else
            {
                // x64: 12-byte movabs rax, addr; jmp rax
                _patchSize = 12;
                _hookBytes = new byte[12];
                _hookBytes[0] = 0x48;
                _hookBytes[1] = 0xB8;
                var bytes = BitConverter.GetBytes((ulong)detourAddress);
                Array.Copy(bytes, 0, _hookBytes, 2, 8);
                _hookBytes[10] = 0xFF;
                _hookBytes[11] = 0xE0;
            }

            _originalBytes = new byte[_patchSize];

            VirtualProtect(targetAddress, (UIntPtr)_patchSize, 0x40, out uint oldProtect); // PAGE_EXECUTE_READWRITE
            Marshal.Copy(targetAddress, _originalBytes, 0, _patchSize);
            VirtualProtect(targetAddress, (UIntPtr)_patchSize, oldProtect, out _);
        }

        public void Enable()
        {
            VirtualProtect(_targetAddress, (UIntPtr)_patchSize, 0x40, out uint oldProtect);
            Marshal.Copy(_hookBytes, 0, _targetAddress, _patchSize);
            VirtualProtect(_targetAddress, (UIntPtr)_patchSize, oldProtect, out _);
            FlushInstructionCache(GetCurrentProcess(), _targetAddress, (UIntPtr)_patchSize);
        }

        public void Disable()
        {
            VirtualProtect(_targetAddress, (UIntPtr)_patchSize, 0x40, out uint oldProtect);
            Marshal.Copy(_originalBytes, 0, _targetAddress, _patchSize);
            VirtualProtect(_targetAddress, (UIntPtr)_patchSize, oldProtect, out _);
            FlushInstructionCache(GetCurrentProcess(), _targetAddress, (UIntPtr)_patchSize);
        }
    }

    private static void LogToFile(string message)
    {
        lock (LogLock)
        {
            try
            {
                File.AppendAllText(LogFilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [Thread {GetCurrentThreadId()}] {message}\r\n");
            }
            catch
            {
                // Ignore log failures
            }
        }
    }

    private static string ToHexDump(IntPtr buffer, uint size)
    {
        if (buffer == IntPtr.Zero || size == 0)
        {
            return string.Empty;
        }

        uint limit = Math.Min(size, 512);
        var sb = new StringBuilder((int)(limit * 3));
        byte* p = (byte*)buffer;
        for (uint i = 0; i < limit; i++)
        {
            sb.Append(p[i].ToString("X2"));
            if (i < limit - 1)
            {
                sb.Append(' ');
            }
        }
        if (size > limit)
        {
            sb.Append(" ... (truncated)");
        }
        return sb.ToString();
    }

    [UnmanagedCallersOnly(EntryPoint = "DetourDeviceIoControl", CallConvs = [typeof(CallConvStdcall)])]
    public static int DetourDeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        uint* lpBytesReturned,
        IntPtr lpOverlapped)
    {
        var inHex = ToHexDump(lpInBuffer, nInBufferSize);
        LogToFile($"DeviceIoControl: hDevice=0x{hDevice:X}, IoControlCode=0x{dwIoControlCode:X8}, InSize={nInBufferSize}, OutSize={nOutBufferSize}, InBuffer=[{inHex}]");

        int result = CallOriginalDeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);

        uint returnedBytes = lpBytesReturned != null ? *lpBytesReturned : 0;
        var outHex = ToHexDump(lpOutBuffer, returnedBytes);
        LogToFile($"DeviceIoControl Result: result={result}, BytesReturned={returnedBytes}, OutBuffer=[{outHex}]");

        return result;
    }

    [UnmanagedCallersOnly(EntryPoint = "DetourFilterSendMessage", CallConvs = [typeof(CallConvStdcall)])]
    public static int DetourFilterSendMessage(
        IntPtr hPort,
        IntPtr lpInBuffer,
        uint dwInBufferSize,
        IntPtr lpOutBuffer,
        uint dwOutBufferSize,
        uint* lpBytesReturned)
    {
        var inHex = ToHexDump(lpInBuffer, dwInBufferSize);
        LogToFile($"FilterSendMessage: hPort=0x{hPort:X}, InSize={dwInBufferSize}, OutSize={dwOutBufferSize}, InBuffer=[{inHex}]");

        int result = CallOriginalFilterSendMessage(hPort, lpInBuffer, dwInBufferSize, lpOutBuffer, dwOutBufferSize, lpBytesReturned);

        uint returnedBytes = lpBytesReturned != null ? *lpBytesReturned : 0;
        var outHex = ToHexDump(lpOutBuffer, returnedBytes);
        LogToFile($"FilterSendMessage Result: HRESULT=0x{result:X8}, BytesReturned={returnedBytes}, OutBuffer=[{outHex}]");

        return result;
    }

    public static int CallOriginalDeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        uint* lpBytesReturned,
        IntPtr lpOverlapped)
    {
        if (_deviceIoControlHook == null)
        {
            bool result = OriginalDeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, out uint bytesRet, lpOverlapped);
            if (lpBytesReturned != null)
            {
                *lpBytesReturned = bytesRet;
            }
            return result ? 1 : 0;
        }
        
        lock (_deviceIoControlHook.Lock)
        {
            _deviceIoControlHook.Disable();
            try
            {
                bool result = OriginalDeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, out uint bytesRet, lpOverlapped);
                if (lpBytesReturned != null)
                {
                    *lpBytesReturned = bytesRet;
                }
                return result ? 1 : 0;
            }
            finally
            {
                _deviceIoControlHook.Enable();
            }
        }
    }

    public static int CallOriginalFilterSendMessage(
        IntPtr hPort,
        IntPtr lpInBuffer,
        uint dwInBufferSize,
        IntPtr lpOutBuffer,
        uint dwOutBufferSize,
        uint* lpBytesReturned)
    {
        if (_filterSendMessageHook == null)
        {
            int result = OriginalFilterSendMessage(hPort, lpInBuffer, dwInBufferSize, lpOutBuffer, dwOutBufferSize, out uint bytesRet);
            if (lpBytesReturned != null)
            {
                *lpBytesReturned = bytesRet;
            }
            return result;
        }
        
        lock (_filterSendMessageHook.Lock)
        {
            _filterSendMessageHook.Disable();
            try
            {
                int result = OriginalFilterSendMessage(hPort, lpInBuffer, dwInBufferSize, lpOutBuffer, dwOutBufferSize, out uint bytesRet);
                if (lpBytesReturned != null)
                {
                    *lpBytesReturned = bytesRet;
                }
                return result;
            }
            finally
            {
                _filterSendMessageHook.Enable();
            }
        }
    }

    private static class ProbeRuntime
    {
        private static readonly object Sync = new();
        private static readonly WndProcDelegate WndProc = WindowProc;
        private static nint _windowHandle;
        private static uint _windowThreadId;
        private static nint _replyHwnd;
        private static Timer? _heartbeatTimer;
        private static long _lastUiHeartbeatMs;
        private static bool _running;

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

            InitializeApiHooks();

            var thread = new Thread(MessageThreadMain)
            {
                IsBackground = true,
                Name = "ProxiFyre probe message loop"
            };
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
        }

        private static void InitializeApiHooks()
        {
            try
            {
                LogToFile("Initializing API Hooks in target process...");

                var hKernel32 = GetModuleHandleWString("kernel32.dll");
                if (hKernel32 == IntPtr.Zero)
                {
                    LogToFile("Failed to get kernel32.dll handle.");
                    return;
                }

                var pDeviceIoControl = GetProcAddress(hKernel32, "DeviceIoControl");
                if (pDeviceIoControl != IntPtr.Zero)
                {
                    IntPtr detour = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr, uint, IntPtr, uint, uint*, IntPtr, int>)&DetourDeviceIoControl;
                    _deviceIoControlHook = new Hook(pDeviceIoControl, detour);
                    _deviceIoControlHook.Enable();
                    LogToFile("DeviceIoControl Hooked successfully.");
                }
                else
                {
                    LogToFile("DeviceIoControl export not found in kernel32.dll.");
                }

                var hFltLib = LoadLibraryW("fltlib.dll");
                if (hFltLib != IntPtr.Zero)
                {
                    var pFilterSendMessage = GetProcAddress(hFltLib, "FilterSendMessage");
                    if (pFilterSendMessage != IntPtr.Zero)
                    {
                        IntPtr detour = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, IntPtr, uint, uint*, int>)&DetourFilterSendMessage;
                        _filterSendMessageHook = new Hook(pFilterSendMessage, detour);
                        _filterSendMessageHook.Enable();
                        LogToFile("FilterSendMessage Hooked successfully.");
                    }
                    else
                    {
                        LogToFile("FilterSendMessage export not found in fltlib.dll.");
                    }
                }
                else
                {
                    LogToFile("fltlib.dll not found/loaded.");
                }
            }
            catch (Exception ex)
            {
                LogToFile($"Failed to initialize hooks: {ex}");
            }
        }

        private static void MessageThreadMain()
        {
            try
            {
                _windowThreadId = GetCurrentThreadId();
                _windowHandle = CreateMessageWindow();
                MarkUiHeartbeat();
                _heartbeatTimer = new Timer(CheckUiHeartbeat, null, UiHeartbeatCheckIntervalMs, UiHeartbeatCheckIntervalMs);
                LogToFile("Probe message window created.");
                SendEvent("loaded", $"ProxiFyre Probe loaded in {Process.GetCurrentProcess().ProcessName}.exe pid={Environment.ProcessId}", running: false);

                MSG message;
                while (GetMessageW(&message, nint.Zero, 0, 0))
                {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
            catch (Exception ex)
            {
                LogToFile($"Probe message loop failed: {ex}");
                SendEvent("error", $"Probe message loop failed: {ex.Message}", running: false);
            }
            finally
            {
                _heartbeatTimer?.Dispose();
                _heartbeatTimer = null;
                CleanupHooks();
                LogToFile("Probe message loop is exiting.");
            }
        }

        private static void CleanupHooks()
        {
            try
            {
                if (_deviceIoControlHook != null)
                {
                    lock (_deviceIoControlHook.Lock)
                    {
                        _deviceIoControlHook.Disable();
                    }
                    _deviceIoControlHook = null;
                    LogToFile("DeviceIoControl hook disabled and removed.");
                }
                if (_filterSendMessageHook != null)
                {
                    lock (_filterSendMessageHook.Lock)
                    {
                        _filterSendMessageHook.Disable();
                    }
                    _filterSendMessageHook = null;
                    LogToFile("FilterSendMessage hook disabled and removed.");
                }
            }
            catch (Exception ex)
            {
                LogToFile($"Error cleanup hooks: {ex}");
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

                _ = ChangeWindowMessageFilter(ModuleMessageProtocol.WmCopyData, MsgfltAdd);

                return handle;
            }
        }

        private static nint WindowProc(nint hWnd, uint msg, nint wParam, nint lParam)
        {
            try
            {
                if (msg == ModuleMessageProtocol.WmCopyData)
                {
                    return HandleCopyData(lParam) ? 1 : 0;
                }

                if (msg == WmClose)
                {
                    CleanupHooks();
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
                LogToFile($"WindowProc failed: {ex}");
                SendEvent("error", ex.Message, running: _running);
                return 0;
            }

            return DefWindowProcW(hWnd, msg, wParam, lParam);
        }

        private static bool HandleCopyData(nint lParam)
        {
            var copyData = Marshal.PtrToStructure<COPYDATASTRUCT>(lParam);
            if (copyData.dwData != ModuleMessageProtocol.CommandDataId || copyData.cbData <= 2 || copyData.lpData == nint.Zero)
            {
                return false;
            }

            var payload = Marshal.PtrToStringUni(copyData.lpData, (copyData.cbData / 2) - 1);
            if (string.IsNullOrWhiteSpace(payload) || !ModuleMessageProtocol.TryParse(payload, out var values))
            {
                return false;
            }

            var replyHwnd = ModuleMessageProtocol.GetReplyHwnd(values);
            if (replyHwnd != nint.Zero)
            {
                _replyHwnd = replyHwnd;
            }

            if (!values.TryGetValue("command", out var command))
            {
                return false;
            }

            MarkUiHeartbeat();

            switch (command.ToUpperInvariant())
            {
                case "HEARTBEAT":
                    return true;
                case "PING":
                    SendEvent("status", $"Probe active (PID={Environment.ProcessId})", running: _running);
                    return true;
                case "RUN":
                    _running = true;
                    SendEvent("running", $"Probe active (PID={Environment.ProcessId})", running: true, pid: Environment.ProcessId);
                    return true;
                case "RELOAD":
                    SendEvent("reloaded", "Probe config reloaded", running: _running);
                    return true;
                case "STOP":
                    _running = false;
                    CleanupHooks();
                    SendEvent("stopped", "Probe stopped, hooks disabled", running: false);
                    return true;
                default:
                    SendEvent("error", $"Unknown probe command: {command}", running: _running);
                    return false;
            }
        }

        private static void MarkUiHeartbeat()
        {
            Interlocked.Exchange(ref _lastUiHeartbeatMs, Environment.TickCount64);
        }

        private static void CheckUiHeartbeat(object? state)
        {
            try
            {
                if (!_running)
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

                LogToFile($"UI heartbeat lost for {elapsedMs} ms; disabling hooks.");
                CleanupHooks();
                _running = false;
                SendEvent("stopped", "UI heartbeat lost", running: false);
            }
            catch (Exception ex)
            {
                LogToFile($"UI heartbeat check failed: {ex}");
            }
        }

        private static void SendEvent(string eventName, string text, bool? running = null, int? pid = null)
        {
            var target = _replyHwnd;
            if (target == nint.Zero)
            {
                return;
            }

            var payload = ModuleMessageProtocol.BuildEvent(eventName, text, running, pid);
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

                nint temp;
                _ = NativeCopyData.SendMessageTimeoutW(
                    targetWindow,
                    ModuleMessageProtocol.WmCopyData,
                    _windowHandle,
                    (nint)(&copyData),
                    SmtoAbortIfHung,
                    CopyDataTimeoutMs,
                    out temp);
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
