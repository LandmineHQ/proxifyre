using System.Windows.Controls;

namespace ProxiFyre;

public partial class TrafficStatusBar : UserControl
{
    public TrafficStatusBar()
    {
        InitializeComponent();
    }

    public void SetTrafficStatus(string uploadText, string downloadText, string? tooltip = null)
    {
        TrafficUploadText.Text = uploadText;
        TrafficDownloadText.Text = downloadText;
        ToolTip = tooltip;
    }
}
