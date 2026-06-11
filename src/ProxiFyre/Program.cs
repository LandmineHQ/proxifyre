using System.Runtime.InteropServices;
using System.Windows;

namespace ProxiFyre;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            MessageBox.Show("This program requires Windows and WinpkFilter.", "ProxiFyre", MessageBoxButton.OK, MessageBoxImage.Error);
            return 1;
        }

        if (args.Length > 0)
        {
            return Cli.RunAsync(args).GetAwaiter().GetResult();
        }

        var app = new App();
        app.InitializeComponent();
        app.Run(new MainWindow());
        return 0;
    }
}
