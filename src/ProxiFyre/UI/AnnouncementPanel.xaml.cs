using System.Windows;
using System.Windows.Controls;

namespace ProxiFyre;

public partial class AnnouncementPanel : UserControl
{
    public AnnouncementPanel()
    {
        InitializeComponent();
    }

    public event EventHandler? DismissRequested;

    public void ShowAnnouncement(string text)
    {
        AnnouncementText.Text = text;
        Visibility = Visibility.Visible;
    }

    public void HideAnnouncement()
    {
        AnnouncementText.Text = string.Empty;
        Visibility = Visibility.Collapsed;
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        DismissRequested?.Invoke(this, EventArgs.Empty);
    }
}
