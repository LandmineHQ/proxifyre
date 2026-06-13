using System.Windows;
using System.Windows.Controls;

namespace ProxiFyre;

public partial class RuntimeInfoTab : UserControl
{
    public RuntimeInfoTab()
    {
        InitializeComponent();
    }

    public event EventHandler? ReloadRequested;

    public void SetConfigPath(string configPath)
    {
        ConfigPathText.Text = configPath;
    }

    public void SetCoreProcessInfo(string text, string networkOwnerHint)
    {
        CoreProcessText.Text = text;
        NetworkOwnerHintText.Text = networkOwnerHint;
    }

    private void ReloadButton_Click(object sender, RoutedEventArgs e)
    {
        ReloadRequested?.Invoke(this, EventArgs.Empty);
    }
}
