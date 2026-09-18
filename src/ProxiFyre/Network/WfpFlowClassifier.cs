using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ProxiFyre;

internal sealed class WfpFlowClassifier : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const int ErrorSemTimeout = 121;
    private const int ErrorTimeout = 1460;

    private readonly SafeFileHandle _handle;
    private readonly Action<WfpFlowEvent, string> _log;
    private CancellationTokenSource? _cts;
    private Task? _loopTask;

    private WfpFlowClassifier(SafeFileHandle handle, Action<WfpFlowEvent, string> log)
    {
        _handle = handle;
        _log = log;
    }

    public static bool TryOpen(Action<string>? log, out WfpFlowClassifier? classifier)
    {
        classifier = null;
        var handle = CreateFile(
            WfpProtocol.DevicePath,
            GenericRead | GenericWrite,
            (uint)FileShare.ReadWrite,
            IntPtr.Zero,
            OpenExisting,
            FileAttributeNormal,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            return false;
        }

        classifier = new WfpFlowClassifier(
            handle,
            (_, message) => log?.Invoke(message));
        return true;
    }

    public void Start(
        Func<WfpFlowEvent, bool> decide,
        CancellationToken cancellationToken)
    {
        if (_loopTask is not null)
        {
            throw new InvalidOperationException("WFP classifier is already running.");
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _loopTask = Task.Run(() => RunAsync(decide, _cts.Token), CancellationToken.None);
    }

    private async Task RunAsync(Func<WfpFlowEvent, bool> decide, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var eventBuffer = new byte[Marshal.SizeOf<WfpFlowEvent>()];
            if (!DeviceIoControl(
                    _handle,
                    WfpProtocol.IoctlGetEvent,
                    null,
                    0,
                    eventBuffer,
                    eventBuffer.Length,
                    out var bytesReturned,
                    IntPtr.Zero))
            {
                var error = Marshal.GetLastWin32Error();
                if (error is ErrorSemTimeout or ErrorTimeout)
                {
                    continue;
                }

                throw new Win32Exception(error, "WFP classifier get-event failed.");
            }

            if (bytesReturned < Marshal.SizeOf<WfpFlowEvent>())
            {
                continue;
            }

            var flow = ReadEvent(eventBuffer);
            flow.LocalAddress ??= [];
            flow.RemoteAddress ??= [];

            var permit = true;
            try
            {
                _ = decide(flow);
            }
            catch (Exception ex)
            {
                _log(flow, $"WFP classifier decision failed: {ex.Message}");
            }

            var verdict = new WfpVerdict
            {
                EventId = flow.EventId,
                Decision = permit ? WfpDecision.Permit : WfpDecision.Permit
            };
            var verdictBuffer = new byte[Marshal.SizeOf<WfpVerdict>()];
            WriteVerdict(verdictBuffer, verdict);

            if (!DeviceIoControl(
                    _handle,
                    WfpProtocol.IoctlCompleteEvent,
                    verdictBuffer,
                    verdictBuffer.Length,
                    null,
                    0,
                    out _,
                    IntPtr.Zero))
            {
                _log(flow, $"WFP classifier complete-event failed: {new Win32Exception(Marshal.GetLastWin32Error()).Message}");
            }
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        try
        {
            _loopTask?.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
        }

        _cts?.Dispose();
        _handle.Dispose();
    }

    private static WfpFlowEvent ReadEvent(byte[] buffer)
    {
        var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            return Marshal.PtrToStructure<WfpFlowEvent>(handle.AddrOfPinnedObject());
        }
        finally
        {
            handle.Free();
        }
    }

    private static void WriteVerdict(byte[] buffer, WfpVerdict verdict)
    {
        var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            Marshal.StructureToPtr(verdict, handle.AddrOfPinnedObject(), false);
        }
        finally
        {
            handle.Free();
        }
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint ioControlCode,
        byte[]? inBuffer,
        int inBufferSize,
        byte[]? outBuffer,
        int outBufferSize,
        out int bytesReturned,
        IntPtr overlapped);
}
