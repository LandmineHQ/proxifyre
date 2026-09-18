using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace ProxiFyre;

internal static class UuElevation
{
    public const string ElevatedUiArgument = "--uu-elevated-ui";

    public static bool IsElevated
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public static bool IsElevatedUiLaunch(string[] args)
    {
        return args.Length == 1
            && args[0].Equals(ElevatedUiArgument, StringComparison.OrdinalIgnoreCase);
    }

    public static bool TryRestartElevated()
    {
        var executablePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return false;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = ElevatedUiArgument,
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Normal
            });
            return true;
        }
        catch (Win32Exception)
        {
            return false;
        }
    }
}
