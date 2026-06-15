using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ProxiFyre;

internal static class ModuleProcessLocator
{
    public static ModuleTargetProcess FindByConfiguredName(string configuredProcessName)
    {
        var target = FindAllByConfiguredName(configuredProcessName).FirstOrDefault();
        if (target is not null)
        {
            return target;
        }

        var processName = AppConfiguration.NormalizeCoreProcessName(configuredProcessName);
        throw new InvalidOperationException($"未找到模组目标进程：{processName}");
    }

    public static bool TryFindByConfiguredName(string configuredProcessName, out ModuleTargetProcess targetProcess)
    {
        targetProcess = FindAllByConfiguredName(configuredProcessName).FirstOrDefault()!;
        return targetProcess is not null;
    }

    public static IReadOnlyList<ModuleTargetProcess> FindAllByConfiguredName(string configuredProcessName)
    {
        var processName = AppConfiguration.NormalizeCoreProcessName(configuredProcessName);
        var lookupName = Path.GetFileNameWithoutExtension(processName);
        var processes = Process.GetProcessesByName(lookupName)
            .OrderBy(candidate => candidate.Id)
            .ToArray();

        if (processes.Length == 0)
        {
            return [];
        }

        try
        {
            return processes
                .Select(process =>
                {
                    var name = process.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                        ? process.ProcessName
                        : process.ProcessName + ".exe";

                    return new ModuleTargetProcess(process.Id, name, TryGetProcessImagePath(process.Id));
                })
                .ToArray();
        }
        finally
        {
            foreach (var process in processes)
            {
                process.Dispose();
            }
        }
    }

    public static bool IsProcessAlive(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (Win32Exception)
        {
            return true;
        }
    }

    private static string? TryGetProcessImagePath(int pid)
    {
        var processHandle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (processHandle == nint.Zero)
        {
            return null;
        }

        try
        {
            var builder = new StringBuilder(32768);
            var capacity = builder.Capacity;
            if (!QueryFullProcessImageName(processHandle, 0, builder, ref capacity))
            {
                return null;
            }

            var path = builder.ToString();
            return string.IsNullOrWhiteSpace(path) ? null : path;
        }
        finally
        {
            CloseHandle(processHandle);
        }
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern nint OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId);

    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        nint processHandle,
        int flags,
        StringBuilder exeName,
        ref int size);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);
}

internal sealed record ModuleTargetProcess(int ProcessId, string ProcessName, string? ProcessPath);
