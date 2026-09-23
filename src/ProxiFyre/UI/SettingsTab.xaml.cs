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

    public event EventHandler<DetailedLoggingToggleRequestedEventArgs>? DetailedLoggingToggleRequested;

    private void UuPatchToggleButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not ToggleButton toggle)
        {
            return;
        }

        var enabled = toggle.IsChecked == true;
        UuPatchToggleRequested?.Invoke(this, new UuPatchToggleRequestedEventArgs(enabled));
    }

    private void DetailedLoggingToggleButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not ToggleButton toggle)
        {
            return;
        }

        DetailedLoggingToggleRequested?.Invoke(
            this,
            new DetailedLoggingToggleRequestedEventArgs(toggle.IsChecked == true));
    }
}

public sealed class DetailedLoggingToggleRequestedEventArgs(bool enabled) : EventArgs
{
    public bool Enabled { get; } = enabled;
}
