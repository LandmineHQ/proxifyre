using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProxiFyre;

/// <summary>
/// UI-side telemetry pipe server. The injected relay module connects to this
/// pipe and streams one TrafficSnapshot per second. This keeps high-frequency
/// network speed data out of the log files and off the WM_COPYDATA control channel.
/// </summary>
internal sealed class TrafficTelemetryServer : IDisposable
{
    private readonly Action<TrafficSnapshot> _onSnapshot;
    private readonly Action<string>? _log;
    private readonly string _pipeName;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loopTask;
    private bool _disposed;

    public TrafficTelemetryServer(
        Action<TrafficSnapshot> onSnapshot,
        Action<string>? log = null,
        string? pipeName = null)
    {
        _onSnapshot = onSnapshot;
        _log = log;
        _pipeName = string.IsNullOrWhiteSpace(pipeName)
            ? TrafficTelemetryProtocol.PipeName
            : pipeName;
    }

    public string PipeName => _pipeName;

    public void Start()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(TrafficTelemetryServer));
        }

        _loopTask = Task.Run(AcceptLoopAsync);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                await using var server = CreateServer();

                await server.WaitForConnectionAsync(_cts.Token).ConfigureAwait(false);
                await ReadLoopAsync(server).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_cts.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _log?.Invoke($"Traffic telemetry pipe error: {ex.Message}");
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), _cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    internal NamedPipeServerStream CreateServer()
    {
        var server = new NamedPipeServerStream(
            _pipeName,
            PipeDirection.In,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        try
        {
            SetMediumIntegrityLabel(server.SafePipeHandle);
        }
        catch (Exception ex)
        {
            _log?.Invoke(
                $"Traffic telemetry could not set the medium integrity label: {ex.Message}");
        }

        return server;
    }

    private static void SetMediumIntegrityLabel(SafePipeHandle pipeHandle)
    {
        // Keep the UI elevated while allowing same-user, non-elevated relay
        // processes to write telemetry through the pipe.
        const uint labelSecurityInformation = 0x00000010;
        const uint kernelObject = 6;
        const uint sddlRevision1 = 1;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                "S:(ML;;NW;;;ME)",
                sddlRevision1,
                out var descriptor,
                out _))
        {
            throw new InvalidOperationException(
                "ConvertStringSecurityDescriptorToSecurityDescriptor failed.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        }

        try
        {
            if (!GetSecurityDescriptorSacl(
                    descriptor,
                    out _,
                    out var systemAcl,
                    out _))
            {
                throw new InvalidOperationException(
                    "GetSecurityDescriptorSacl failed.",
                    new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
            }

            var result = SetSecurityInfo(
                pipeHandle.DangerousGetHandle(),
                kernelObject,
                labelSecurityInformation,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                systemAcl);
            if (result != 0)
            {
                throw new InvalidOperationException(
                    "SetSecurityInfo could not set the medium integrity label.",
                    new System.ComponentModel.Win32Exception((int)result));
            }
        }
        finally
        {
            _ = LocalFree(descriptor);
        }
    }

    internal static bool HasMediumIntegrityLabel(SafePipeHandle pipeHandle)
    {
        const uint labelSecurityInformation = 0x00000010;
        const uint kernelObject = 6;
        const uint sddlRevision1 = 1;
        var result = GetSecurityInfo(
            pipeHandle.DangerousGetHandle(),
            kernelObject,
            labelSecurityInformation,
            out _,
            out _,
            out _,
            out _,
            out var descriptor);
        if (result != 0 || descriptor == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(
                    descriptor,
                    sddlRevision1,
                    labelSecurityInformation,
                    out var sddl,
                    out _))
            {
                return false;
            }

            try
            {
                return Marshal.PtrToStringUni(sddl)?.Contains(
                    "ML;;NW;;;ME",
                    StringComparison.OrdinalIgnoreCase) == true;
            }
            finally
            {
                _ = LocalFree(sddl);
            }
        }
        finally
        {
            _ = LocalFree(descriptor);
        }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint stringSecurityDescriptorRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorSacl(
        IntPtr securityDescriptor,
        [MarshalAs(UnmanagedType.Bool)] out bool saclPresent,
        out IntPtr sacl,
        [MarshalAs(UnmanagedType.Bool)] out bool saclDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(
        IntPtr handle,
        uint objectType,
        uint securityInfo,
        out IntPtr owner,
        out IntPtr group,
        out IntPtr dacl,
        out IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
        IntPtr securityDescriptor,
        uint securityDescriptorRevision,
        uint securityInformation,
        out IntPtr stringSecurityDescriptor,
        out uint stringSecurityDescriptorLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(
        IntPtr handle,
        uint objectType,
        uint securityInfo,
        IntPtr owner,
        IntPtr group,
        IntPtr dacl,
        IntPtr sacl);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    private async Task ReadLoopAsync(NamedPipeServerStream server)
    {
        using var reader = new StreamReader(server, Encoding.UTF8);
        while (!_cts.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(_cts.Token).ConfigureAwait(false);
            if (line is null)
            {
                return; // module disconnected; accept the next connection
            }

            if (TrafficTelemetryProtocol.TryParse(line, out _, out var snapshot))
            {
                _onSnapshot(snapshot);
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cts.Cancel();
        _cts.Dispose();
        _loopTask = null;
    }
}
