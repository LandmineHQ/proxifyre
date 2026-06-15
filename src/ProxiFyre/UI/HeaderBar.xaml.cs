using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace ProxiFyre;

public partial class HeaderBar : UserControl
{
    public HeaderBar()
    {
        InitializeComponent();
    }

    public event EventHandler? OpenSourceRequested;

    public event EventHandler? StartStopRequested;

    public bool StartStopEnabled
    {
        get => StartStopButton.IsEnabled;
        set => StartStopButton.IsEnabled = value;
    }

    public void SetVersionChecking(string localVersion)
    {
        LocalVersionText.Text = localVersion;
        RemoteVersionText.Text = "检查中";
        RemoteVersionText.Foreground = BrushFromHex("#667085");
    }

    public void SetRemoteVersion(string version, bool hasUpdate)
    {
        RemoteVersionText.Text = version;
        RemoteVersionText.Foreground = BrushFromHex(hasUpdate ? "#B54708" : "#067647");
    }

    public void SetVersionFailed()
    {
        RemoteVersionText.Text = "获取失败";
        RemoteVersionText.Foreground = BrushFromHex("#C73535");
    }

    public void SetRunning(bool running)
    {
        StatusText.Text = running ? "模组运行中" : "未运行";
        StatusText.Foreground = BrushFromHex(running ? "#067647" : "#475467");
        StatusDot.Fill = BrushFromHex(running ? "#17B26A" : "#98A2B3");
        StatusBadge.Background = BrushFromHex(running ? "#ECFDF3" : "#EEF2F7");
        StartStopButton.Background = BrushFromHex(running ? "#C73535" : "#16803C");
        StartStopButtonText.Text = running ? "停止转发" : "载入模组";
        StartStopIcon.Data = Geometry.Parse(running ? "M 2 1 H 6 V 13 H 2 Z M 9 1 H 13 V 13 H 9 Z" : "M 2 1 L 13 7 L 2 13 Z");
    }

    private void SourceButton_Click(object sender, RoutedEventArgs e)
    {
        OpenSourceRequested?.Invoke(this, EventArgs.Empty);
    }

    private void StartStopButton_Click(object sender, RoutedEventArgs e)
    {
        StartStopRequested?.Invoke(this, EventArgs.Empty);
    }

    private static SolidColorBrush BrushFromHex(string value)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(value));
        brush.Freeze();
        return brush;
    }
}
