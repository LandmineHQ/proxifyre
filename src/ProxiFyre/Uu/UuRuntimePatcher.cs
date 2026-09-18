using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace ProxiFyre;

internal enum UuModulePatchState
{
    Ready,
    PartiallyPatched,
    AlreadyPatched,
    Unsupported,
    Error
}

internal sealed class UuTargetInspection
{
    public required UuPatchTarget Target { get; init; }

    public required bool IsOriginal { get; init; }

    public required bool IsPatched { get; init; }
}

internal sealed class UuModuleInspection
{
    public required int ProcessId { get; init; }

    public required string ProcessName { get; init; }

    public required string ModulePath { get; init; }

    public required nint ModuleBaseAddress { get; init; }

    public required UuPatchProfile Profile { get; init; }

    public required UuModulePatchState State { get; init; }

    public required IReadOnlyList<UuTargetInspection> Targets { get; init; }

    public string? Error { get; init; }

    public int OriginalCount => Targets.Count(target => target.IsOriginal);

    public int PatchedCount => Targets.Count(target => target.IsPatched);

    public bool CanApply => State is UuModulePatchState.Ready or UuModulePatchState.PartiallyPatched;
}

internal sealed class UuPatchInspection
{
    public required bool UuRunning { get; init; }

    public required IReadOnlyList<UuModuleInspection> Modules { get; init; }

    public required IReadOnlyList<string> Errors { get; init; }

    public bool HasPatchableModule => Modules.Any(module => module.CanApply);

    public bool HasPatchedModule => Modules.Any(module =>
        module.State is UuModulePatchState.AlreadyPatched or UuModulePatchState.PartiallyPatched);
}

internal sealed record UuPatchOperationResult(
    bool Success,
    int ProcessCount,
    int TargetCount,
    string Message);

internal sealed class UuRuntimePatcher
{
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessVmOperation = 0x0008;
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessVmWrite = 0x0020;
    private const uint ProcessSuspendResume = 0x0800;
    private const uint PageExecuteReadWrite = 0x40;

    private readonly IReadOnlyList<UuPatchProfile> _profiles;

    public UuRuntimePatcher()
        : this(UuPatchCatalog.LoadDefault())
    {
    }

    internal UuRuntimePatcher(IReadOnlyList<UuPatchProfile> profiles)
    {
        _profiles = profiles;
    }

    public UuPatchInspection Inspect()
    {
        var modules = new List<UuModuleInspection>();
        var errors = new List<string>();
        var processes = GetUuProcesses();
        try
        {
            foreach (var process in processes)
            {
                try
                {
                    var module = FindLocalProxyModule(process);
                    if (module is null)
                    {
                        continue;
                    }

                    modules.Add(InspectModule(process, module));
                }
                catch (Exception ex)
                {
                    errors.Add($"{process.ProcessName} ({process.Id}): {ex.Message}");
                }
            }
        }
        finally
        {
            foreach (var process in processes)
            {
                process.Dispose();
            }
        }

        return new UuPatchInspection
        {
            UuRunning = processes.Count > 0,
            Modules = modules,
            Errors = errors
        };
    }

    public UuPatchOperationResult Apply()
    {
        return PatchLoadedModules(writePatchedBytes: true);
    }

    public UuPatchOperationResult Restore()
    {
        return PatchLoadedModules(writePatchedBytes: false);
    }

    private UuPatchOperationResult PatchLoadedModules(bool writePatchedBytes)
    {
        var inspection = Inspect();
        if (!inspection.UuRunning)
        {
            return new UuPatchOperationResult(false, 0, 0, "未检测到正在运行的 UU 应用。");
        }

        if (inspection.Modules.Count == 0)
        {
            return new UuPatchOperationResult(
                false,
                0,
                0,
                "检测到 UU，但 local_proxy.dll 尚未加载。请先在 UU 中启动一次游戏加速。");
        }

        var changedProcesses = 0;
        var changedTargets = 0;
        var failures = new List<string>();
        foreach (var module in inspection.Modules)
        {
            if (module.State is UuModulePatchState.Unsupported or UuModulePatchState.Error)
            {
                failures.Add($"{module.ProcessName} ({module.ProcessId}): {module.Error}");
                continue;
            }

            try
            {
                var changed = WriteModule(module, writePatchedBytes);
                if (changed > 0)
                {
                    changedProcesses++;
                    changedTargets += changed;
                }
            }
            catch (Exception ex)
            {
                failures.Add($"{module.ProcessName} ({module.ProcessId}): {ex.Message}");
            }
        }

        if (failures.Count > 0)
        {
            return new UuPatchOperationResult(
                false,
                changedProcesses,
                changedTargets,
                string.Join(Environment.NewLine, failures));
        }

        var action = writePatchedBytes ? "应用" : "恢复";
        return new UuPatchOperationResult(
            true,
            changedProcesses,
            changedTargets,
            changedTargets == 0
                ? $"所有 local_proxy.dll 实例已经处于目标状态，无需{action}。"
                : $"已对 {changedProcesses} 个进程中的 {changedTargets} 个函数{action}运行时补丁。");
    }

    private UuModuleInspection InspectModule(Process process, ProcessModule module)
    {
        var modulePath = module.FileName;
        if (string.IsNullOrWhiteSpace(modulePath) || !File.Exists(modulePath))
        {
            return CreateErrorModule(process, module, $"找不到模块文件：{modulePath}");
        }

        var fileHash = ComputeSha256(modulePath);
        var profile = UuPatchCatalog.FindByHash(_profiles, fileHash, allowPatchedHash: true);
        if (profile is null)
        {
            return CreateErrorModule(
                process,
                module,
                $"未找到匹配的 local_proxy.dll 版本：{fileHash}");
        }

        using var handle = OpenProcess(
            ProcessQueryInformation | ProcessVmRead,
            process.Id);

        var targets = new List<UuTargetInspection>();
        var mismatches = new List<string>();
        foreach (var target in profile.Targets)
        {
            var address = AddOffset(module.BaseAddress, target.Rva);
            var bytes = ReadBytes(handle, address, target.OriginalBytes.Length);
            var isOriginal = bytes.AsSpan().SequenceEqual(target.OriginalBytes);
            var isPatched = bytes.AsSpan().SequenceEqual(target.PatchedBytes);
            if (!isOriginal && !isPatched)
            {
                mismatches.Add(target.Name);
            }

            targets.Add(new UuTargetInspection
            {
                Target = target,
                IsOriginal = isOriginal,
                IsPatched = isPatched
            });
        }

        if (mismatches.Count > 0)
        {
            return new UuModuleInspection
            {
                ProcessId = process.Id,
                ProcessName = process.ProcessName,
                ModulePath = modulePath,
                ModuleBaseAddress = module.BaseAddress,
                Profile = profile,
                State = UuModulePatchState.Unsupported,
                Targets = targets,
                Error = $"以下函数未找到原始签名或已知补丁：{string.Join(", ", mismatches)}"
            };
        }

        var patchedCount = targets.Count(target => target.IsPatched);
        var state = patchedCount switch
        {
            0 => UuModulePatchState.Ready,
            _ when patchedCount == targets.Count => UuModulePatchState.AlreadyPatched,
            _ => UuModulePatchState.PartiallyPatched
        };

        return new UuModuleInspection
        {
            ProcessId = process.Id,
            ProcessName = process.ProcessName,
            ModulePath = modulePath,
            ModuleBaseAddress = module.BaseAddress,
            Profile = profile,
            State = state,
            Targets = targets
        };
    }

    private static UuModuleInspection CreateErrorModule(
        Process process,
        ProcessModule module,
        string error)
    {
        return new UuModuleInspection
        {
            ProcessId = process.Id,
            ProcessName = process.ProcessName,
            ModulePath = module.FileName ?? string.Empty,
            ModuleBaseAddress = module.BaseAddress,
            Profile = new UuPatchProfile
            {
                Key = "unknown",
                Label = "未知 UU 版本",
                Version = "unknown",
                Sha256 = string.Empty,
                PatchedSha256 = string.Empty,
                Targets = []
            },
            State = UuModulePatchState.Error,
            Targets = [],
            Error = error
        };
    }

    private static int WriteModule(UuModuleInspection module, bool writePatchedBytes)
    {
        using var handle = OpenProcess(
            ProcessQueryInformation
            | ProcessVmOperation
            | ProcessVmRead
            | ProcessVmWrite
            | ProcessSuspendResume,
            module.ProcessId);

        var suspended = SuspendProcess(handle);
        if (!suspended)
        {
            throw new InvalidOperationException("无法暂停 UU 进程，已取消运行时补丁。");
        }

        try
        {
            var writes = new List<(
                nint Address,
                byte[] Bytes,
                byte[] UndoBytes,
                string Name)>();
            foreach (var target in module.Targets)
            {
                var address = AddOffset(module.ModuleBaseAddress, target.Target.Rva);
                var current = ReadBytes(handle, address, target.Target.OriginalBytes.Length);
                var isOriginal = current.AsSpan().SequenceEqual(target.Target.OriginalBytes);
                var isPatched = current.AsSpan().SequenceEqual(target.Target.PatchedBytes);
                if (!isOriginal && !isPatched)
                {
                    throw new InvalidOperationException(
                        $"函数签名已变化，取消写入：{target.Target.Name}");
                }

                if (writePatchedBytes && isOriginal)
                {
                    writes.Add((
                        address,
                        target.Target.PatchedBytes,
                        target.Target.OriginalBytes,
                        target.Target.Name));
                }
                else if (!writePatchedBytes && isPatched)
                {
                    writes.Add((
                        address,
                        target.Target.OriginalBytes,
                        target.Target.PatchedBytes,
                        target.Target.Name));
                }
            }

            var completedWrites = new List<(
                nint Address,
                byte[] UndoBytes,
                string Name)>();
            foreach (var write in writes)
            {
                try
                {
                    WriteBytes(handle, write.Address, write.Bytes, write.Name);
                    completedWrites.Add((write.Address, write.UndoBytes, write.Name));
                }
                catch
                {
                    for (var index = completedWrites.Count - 1; index >= 0; index--)
                    {
                        var completed = completedWrites[index];
                        try
                        {
                            WriteBytes(
                                handle,
                                completed.Address,
                                completed.UndoBytes,
                                completed.Name);
                        }
                        catch
                        {
                        }
                    }

                    throw;
                }
            }

            return writes.Count;
        }
        finally
        {
            ResumeProcess(handle);
        }
    }

    private static IReadOnlyList<Process> GetUuProcesses()
    {
        var processRoots = new[]
        {
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Netease",
                "UU"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Netease",
                "UU")
        };

        var result = new List<Process>();
        foreach (var process in Process.GetProcesses())
        {
            var keep = false;
            try
            {
                var processPath = process.MainModule?.FileName;
                keep = !string.IsNullOrWhiteSpace(processPath)
                    && processRoots.Any(root =>
                        processPath.StartsWith(root, StringComparison.OrdinalIgnoreCase));
                if (!keep)
                {
                    keep = process.ProcessName.Equals("uu", StringComparison.OrdinalIgnoreCase)
                        || process.ProcessName.StartsWith("uu_", StringComparison.OrdinalIgnoreCase);
                }
            }
            catch
            {
                keep = process.ProcessName.Equals("uu", StringComparison.OrdinalIgnoreCase)
                    || process.ProcessName.StartsWith("uu_", StringComparison.OrdinalIgnoreCase);
            }

            if (keep)
            {
                result.Add(process);
            }
            else
            {
                process.Dispose();
            }
        }

        return result;
    }

    private static ProcessModule? FindLocalProxyModule(Process process)
    {
        return process.Modules
            .Cast<ProcessModule>()
            .FirstOrDefault(module =>
                module.ModuleName.Equals("local_proxy.dll", StringComparison.OrdinalIgnoreCase));
    }

    private static SafeProcessHandle OpenProcess(uint access, int processId)
    {
        var handle = NativeMethods.OpenProcess(access, false, processId);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return handle;
    }

    private static byte[] ReadBytes(SafeProcessHandle handle, nint address, int length)
    {
        var buffer = new byte[length];
        if (!NativeMethods.ReadProcessMemory(
                handle,
                address,
                buffer,
                (nuint)buffer.Length,
                out var bytesRead)
            || bytesRead != (nuint)buffer.Length)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"读取 0x{address.ToInt64():X} 失败。");
        }

        return buffer;
    }

    private static void WriteBytes(
        SafeProcessHandle handle,
        nint address,
        byte[] bytes,
        string targetName)
    {
        if (!NativeMethods.VirtualProtectEx(
                handle,
                address,
                (nuint)bytes.Length,
                PageExecuteReadWrite,
                out var oldProtection))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"无法修改 {targetName} 的内存保护。");
        }

        try
        {
            if (!NativeMethods.WriteProcessMemory(
                    handle,
                    address,
                    bytes,
                    (nuint)bytes.Length,
                    out var bytesWritten)
                || bytesWritten != (nuint)bytes.Length)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"写入 {targetName} 失败。");
            }

            NativeMethods.FlushInstructionCache(
                handle,
                address,
                (nuint)bytes.Length);
        }
        finally
        {
            _ = NativeMethods.VirtualProtectEx(
                handle,
                address,
                (nuint)bytes.Length,
                oldProtection,
                out _);
        }
    }

    private static bool SuspendProcess(SafeProcessHandle handle)
    {
        return NativeMethods.NtSuspendProcess(handle.DangerousGetHandle()) >= 0;
    }

    private static void ResumeProcess(SafeProcessHandle handle)
    {
        _ = NativeMethods.NtResumeProcess(handle.DangerousGetHandle());
    }

    private static nint AddOffset(nint baseAddress, uint rva)
    {
        return baseAddress + checked((nint)rva);
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SafeProcessHandle OpenProcess(
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(
            SafeProcessHandle process,
            nint baseAddress,
            [Out] byte[] buffer,
            nuint size,
            out nuint bytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(
            SafeProcessHandle process,
            nint baseAddress,
            [In] byte[] buffer,
            nuint size,
            out nuint bytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtectEx(
            SafeProcessHandle process,
            nint address,
            nuint size,
            uint newProtect,
            out uint oldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FlushInstructionCache(
            SafeProcessHandle process,
            nint baseAddress,
            nuint size);

        [DllImport("ntdll.dll")]
        public static extern int NtSuspendProcess(nint processHandle);

        [DllImport("ntdll.dll")]
        public static extern int NtResumeProcess(nint processHandle);
    }
}
