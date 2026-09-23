using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
namespace ProxiFyre;

public partial class SettingsTab : UserControl
{
    public SettingsTab()
    {
        InitializeComponent();
    }

    public event EventHandler<UuPatchToggleRequestedEventArgs>? UuPatchToggleRequested;

    private void UuPatchToggleButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not ToggleButton toggle)
        {
            return;
        }

        var enabled = toggle.IsChecked == true;
        UuPatchToggleRequested?.Invoke(this, new UuPatchToggleRequestedEventArgs(enabled));
    }
}
