using System.Runtime.InteropServices;
using System.Text;

namespace ProxiFyre;

internal sealed unsafe class ModuleMessageClient : IDisposable
{
    private const int HwndMessage = -3;
    private const uint CopyDataTimeoutMs = 3000;
    private const uint SmtoAbortIfHung = 0x0002;
    private const uint WmClose = 0x0010;
    private const uint WmDestroy = 0x0002;
    private const uint WmNull = 0x0000;

    private readonly AutoResetEvent _windowReady = new(false);
    private readonly WndProcDelegate _wndProc;
    private readonly Thread _thread;
    private bool _disposed;
    private nint _windowHandle;
    private uint _threadId;

    public ModuleMessageClient(Action<ModuleEvent> eventHandler)
    {
        EventHandler = eventHandler;
        _wndProc = WindowProc;
        _thread = new Thread(MessageThreadMain)
        {
            IsBackground = true,
            Name = "ProxiFyre UI module message client"
        };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();

        if (!_windowReady.WaitOne(TimeSpan.FromSeconds(3)) || _windowHandle == nint.Zero)
        {
            throw new InvalidOperationException("Failed to create UI module message window.");
        }
    }

    public nint WindowHandle => _windowHandle;

    private Action<ModuleEvent> EventHandler { get; }

    public bool SendCommand(nint moduleWindow, string commandPayload)
    {
        return SendCommand(moduleWindow, commandPayload, TimeSpan.FromSeconds(5));
    }

    public bool SendCommand(nint moduleWindow, string commandPayload, TimeSpan timeout)
    {
        return SendCopyData(moduleWindow, WindowHandle, ModuleMessageProtocol.CommandDataId, commandPayload, timeout);
    }

    private void MessageThreadMain()
    {
        _threadId = GetCurrentThreadId();
        try
        {
            _windowHandle = CreateMessageWindow();
            _windowReady.Set();

            MSG message;
            while (GetMessageW(&message, nint.Zero, 0, 0))
            {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        finally
        {
            _windowReady.Set();
        }
    }

    private nint CreateMessageWindow()
    {
        nint procPtr = Marshal.GetFunctionPointerForDelegate(_wndProc);
        fixed (char* className = "ProxiFyre.UI.ModuleMessageClient")
        fixed (char* title = "ProxiFyre UI Module Client")
        {
            var wndClass = new WNDCLASSEX
            {
                cbSize = (uint)sizeof(WNDCLASSEX),
                style = 0,
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
                throw new InvalidOperationException($"CreateWindowExW failed. Win32={Marshal.GetLastWin32Error()}");
            }

            return handle;
        }
    }

    private nint WindowProc(nint hWnd, uint msg, nint wParam, nint lParam)
    {
        if (msg == ModuleMessageProtocol.WmCopyData)
        {
            return HandleCopyData(lParam) ? 1 : 0;
        }

        if (msg == WmClose)
        {
            DestroyWindow(hWnd);
            return 0;
        }

        if (msg == WmDestroy)
        {
            PostQuitMessage(0);
            return 0;
        }

        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    private bool HandleCopyData(nint lParam)
    {
        var copyData = Marshal.PtrToStructure<COPYDATASTRUCT>(lParam);
        if (copyData.dwData != ModuleMessageProtocol.EventDataId || copyData.cbData <= 2 || copyData.lpData == nint.Zero)
        {
            return false;
        }

        var payload = Marshal.PtrToStringUni(copyData.lpData, (copyData.cbData / 2) - 1);
        if (string.IsNullOrWhiteSpace(payload) || !ModuleMessageProtocol.TryParse(payload, out var values))
        {
            return false;
        }

        var eventName = values.TryGetValue("event", out var rawEvent) ? rawEvent : "log";
        var text = ModuleMessageProtocol.GetText(values);
        bool? running = values.TryGetValue("running", out _)
            ? ModuleMessageProtocol.GetBool(values, "running")
            : null;
        var pid = values.TryGetValue("pid", out var rawPid) && int.TryParse(rawPid, out var parsedPid)
            ? parsedPid
            : default(int?);

        EventHandler(new ModuleEvent(eventName, text, running, pid));
        return true;
    }

    public static bool SendCopyData(nint targetWindow, nint senderWindow, int dataId, string payload, TimeSpan? timeout = null)
    {
        var timeoutMs = timeout is null
            ? CopyDataTimeoutMs
            : (uint)Math.Clamp(timeout.Value.TotalMilliseconds, 1, uint.MaxValue);
        var bytes = Encoding.Unicode.GetBytes(payload + '\0');
        fixed (byte* bytesPtr = bytes)
        {
            var copyData = new COPYDATASTRUCT
            {
                dwData = dataId,
                cbData = bytes.Length,
                lpData = (nint)bytesPtr
            };

            return SendMessageTimeoutW(
                    targetWindow,
                    ModuleMessageProtocol.WmCopyData,
                    senderWindow,
                    (nint)(&copyData),
                    SmtoAbortIfHung,
                    timeoutMs,
                    out var result) != nint.Zero
                && result != nint.Zero;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_windowHandle != nint.Zero)
        {
            _ = SendMessageW(_windowHandle, WmClose, nint.Zero, nint.Zero);
        }
        else if (_threadId != 0)
        {
            _ = PostThreadMessageW(_threadId, WmNull, nint.Zero, nint.Zero);
        }

        if (!_thread.Join(TimeSpan.FromSeconds(2)) && _threadId != 0)
        {
            _ = PostThreadMessageW(_threadId, WmNull, nint.Zero, nint.Zero);
        }

        _windowReady.Dispose();
    }

    private delegate nint WndProcDelegate(nint hWnd, uint msg, nint wParam, nint lParam);

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

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern uint GetCurrentThreadId();

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
    private static extern void PostQuitMessage(int nExitCode);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMessageW(MSG* lpMsg, nint hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TranslateMessage(MSG* lpMsg);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern nint DispatchMessageW(MSG* lpMsg);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern nint SendMessageTimeoutW(
        nint hWnd,
        uint msg,
        nint wParam,
        nint lParam,
        uint fuFlags,
        uint uTimeout,
        out nint lpdwResult);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern nint SendMessageW(nint hWnd, uint msg, nint wParam, nint lParam);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostThreadMessageW(uint idThread, uint Msg, nint wParam, nint lParam);
}

public sealed record ModuleEvent(string EventName, string Text, bool? Running, int? ProcessId);
