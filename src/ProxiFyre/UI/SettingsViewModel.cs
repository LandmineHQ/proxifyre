using System.Windows.Media;

namespace ProxiFyre;

internal sealed class SettingsViewModel : ObservableObject
{
    private static readonly SolidColorBrush InstallActionBrush = BrushFromHex("#2563EB");
    private static readonly SolidColorBrush InstallActionTextBrush = BrushFromHex("#FFFFFF");
    private static readonly SolidColorBrush UninstallActionBrush = BrushFromHex("#FEE4E2");
    private static readonly SolidColorBrush UninstallActionTextBrush = BrushFromHex("#B42318");
    private static readonly SolidColorBrush InstalledBadgeBrush = BrushFromHex("#ECFDF3");
    private static readonly SolidColorBrush InstalledStatusBrush = BrushFromHex("#067647");
    private static readonly SolidColorBrush MissingBadgeBrush = BrushFromHex("#FEF3F2");
    private static readonly SolidColorBrush MissingStatusBrush = BrushFromHex("#B42318");
    private static readonly SolidColorBrush BusyBadgeBrush = BrushFromHex("#EEF2F7");
    private static readonly SolidColorBrush BusyStatusBrush = BrushFromHex("#475467");

    private string _licenseKey = string.Empty;
    private WinpkFilterStatus _winpkFilterStatus = new(false, "检查中", "正在检查安装状态...", null);
    private bool _isWinpkFilterBusy;
    private string _winpkFilterBusyText = string.Empty;

    public string LicenseKey
    {
        get => _licenseKey;
        private set => SetProperty(ref _licenseKey, value);
    }

    public WinpkFilterStatus WinpkFilterStatus
    {
        get => _winpkFilterStatus;
        private set
        {
            if (SetProperty(ref _winpkFilterStatus, value))
            {
                RefreshWinpkFilterPresentation();
            }
        }
    }

    public bool IsWinpkFilterBusy
    {
        get => _isWinpkFilterBusy;
        private set
        {
            if (SetProperty(ref _isWinpkFilterBusy, value))
            {
                RefreshWinpkFilterPresentation();
            }
        }
    }

    public string WinpkFilterStatusText => IsWinpkFilterBusy ? "处理中" : WinpkFilterStatus.StatusText;

    public string WinpkFilterDetailText => IsWinpkFilterBusy ? _winpkFilterBusyText : WinpkFilterStatus.Detail;

    public string WinpkFilterActionText => WinpkFilterStatus.IsInstalled ? "卸载" : "安装";

    public bool IsWinpkFilterActionEnabled => !IsWinpkFilterBusy;

    public Brush WinpkFilterActionBackground => WinpkFilterStatus.IsInstalled ? UninstallActionBrush : InstallActionBrush;

    public Brush WinpkFilterActionForeground => WinpkFilterStatus.IsInstalled ? UninstallActionTextBrush : InstallActionTextBrush;

    public Brush WinpkFilterBadgeBackground
    {
        get
        {
            if (IsWinpkFilterBusy)
            {
                return BusyBadgeBrush;
            }

            return WinpkFilterStatus.IsInstalled ? InstalledBadgeBrush : MissingBadgeBrush;
        }
    }

    public Brush WinpkFilterStatusForeground
    {
        get
        {
            if (IsWinpkFilterBusy)
            {
                return BusyStatusBrush;
            }

            return WinpkFilterStatus.IsInstalled ? InstalledStatusBrush : MissingStatusBrush;
        }
    }

    public void SetLicenseKey(string? licenseKey)
    {
        LicenseKey = licenseKey ?? string.Empty;
    }

    public void ApplyWinpkFilterStatus(WinpkFilterStatus status)
    {
        WinpkFilterStatus = status;
    }

    public void SetWinpkFilterBusy(string text)
    {
        _winpkFilterBusyText = text;
        OnPropertyChanged(nameof(WinpkFilterDetailText));
        IsWinpkFilterBusy = true;
    }

    public void SetWinpkFilterIdle()
    {
        _winpkFilterBusyText = string.Empty;
        IsWinpkFilterBusy = false;
    }

    private void RefreshWinpkFilterPresentation()
    {
        OnPropertyChanged(nameof(WinpkFilterStatusText));
        OnPropertyChanged(nameof(WinpkFilterDetailText));
        OnPropertyChanged(nameof(WinpkFilterActionText));
        OnPropertyChanged(nameof(IsWinpkFilterActionEnabled));
        OnPropertyChanged(nameof(WinpkFilterActionBackground));
        OnPropertyChanged(nameof(WinpkFilterActionForeground));
        OnPropertyChanged(nameof(WinpkFilterBadgeBackground));
        OnPropertyChanged(nameof(WinpkFilterStatusForeground));
    }

    private static SolidColorBrush BrushFromHex(string value)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(value));
        brush.Freeze();
        return brush;
    }
}
