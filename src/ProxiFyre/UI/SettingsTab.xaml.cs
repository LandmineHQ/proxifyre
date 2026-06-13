using System.Windows;
using System.Windows.Controls;
namespace ProxiFyre;

public partial class SettingsTab : UserControl
{
    public SettingsTab()
    {
        InitializeComponent();
    }

    public event EventHandler? WinpkFilterActionRequested;

    private void WinpkFilterActionButton_Click(object sender, RoutedEventArgs e)
    {
        WinpkFilterActionRequested?.Invoke(this, EventArgs.Empty);
    }
}
