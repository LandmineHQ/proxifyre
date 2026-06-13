using System.Windows.Controls;

namespace ProxiFyre;

public partial class TrafficStatusBar : UserControl
{
    public TrafficStatusBar()
    {
        InitializeComponent();
    }

    public void SetTrafficStatus(string uploadText, string downloadText)
    {
        TrafficUploadText.Text = uploadText;
        TrafficDownloadText.Text = downloadText;
    }
}
