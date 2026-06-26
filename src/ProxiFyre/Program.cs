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

        if (!UiSingleInstanceCoordinator.TryAcquirePrimary(out var singleInstance))
        {
            return 0;
        }

        using (singleInstance)
        {
            var app = new App();
            app.InitializeComponent();
            var mainWindow = new MainWindow();
            singleInstance.StartListening(app.Dispatcher, mainWindow.ShowAndActivate);
            return app.Run(mainWindow);
        }
    }
}
