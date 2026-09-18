using System.Windows.Media;

namespace ProxiFyre;

internal enum UuPatchUiState
{
    Neutral,
    Ready,
    Patched,
    Error
}

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
    private static readonly SolidColorBrush ReadyBadgeBrush = BrushFromHex("#EFF8FF");
    private static readonly SolidColorBrush ReadyStatusBrush = BrushFromHex("#175CD3");
    private static readonly SolidColorBrush NeutralBadgeBrush = BrushFromHex("#F2F4F7");
    private static readonly SolidColorBrush NeutralStatusBrush = BrushFromHex("#475467");

    private WinpkFilterStatus _winpkFilterStatus = new(false, "检查中", "正在检查安装状态...", null);
    private bool _isWinpkFilterBusy;
    private string _winpkFilterBusyText = string.Empty;
    private bool _isUuPatchEnabled;
    private bool _isUuPatchBusy;
    private string _uuPatchBusyText = string.Empty;
    private string _uuPatchStatusText = "未检测";
    private string _uuPatchDetailText = "等待检测正在运行的 UU 应用。";
    private UuPatchUiState _uuPatchUiState = UuPatchUiState.Neutral;

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

    public bool IsUuPatchEnabled
    {
        get => _isUuPatchEnabled;
        set => SetProperty(ref _isUuPatchEnabled, value);
    }

    public bool IsUuPatchBusy
    {
        get => _isUuPatchBusy;
        private set
        {
            if (SetProperty(ref _isUuPatchBusy, value))
            {
                RefreshUuPatchPresentation();
            }
        }
    }

    public bool IsUuPatchActionEnabled => !IsUuPatchBusy;

    public string UuPatchStatusText => IsUuPatchBusy ? "处理中" : _uuPatchStatusText;

    public string UuPatchDetailText => IsUuPatchBusy ? _uuPatchBusyText : _uuPatchDetailText;

    public Brush UuPatchBadgeBackground
    {
        get
        {
            if (IsUuPatchBusy)
            {
                return BusyBadgeBrush;
            }

            return _uuPatchUiState switch
            {
                UuPatchUiState.Ready => ReadyBadgeBrush,
                UuPatchUiState.Patched => InstalledBadgeBrush,
                UuPatchUiState.Error => MissingBadgeBrush,
                _ => NeutralBadgeBrush
            };
        }
    }

    public Brush UuPatchStatusForeground
    {
        get
        {
            if (IsUuPatchBusy)
            {
                return BusyStatusBrush;
            }

            return _uuPatchUiState switch
            {
                UuPatchUiState.Ready => ReadyStatusBrush,
                UuPatchUiState.Patched => InstalledStatusBrush,
                UuPatchUiState.Error => MissingStatusBrush,
                _ => NeutralStatusBrush
            };
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

    public void SetUuPatchEnabled(bool enabled)
    {
        IsUuPatchEnabled = enabled;
    }

    public void SetUuPatchBusy(string text)
    {
        _uuPatchBusyText = text;
        OnPropertyChanged(nameof(UuPatchDetailText));
        IsUuPatchBusy = true;
    }

    public void SetUuPatchIdle()
    {
        _uuPatchBusyText = string.Empty;
        IsUuPatchBusy = false;
    }

    public void ApplyUuPatchStatus(string statusText, string detailText, UuPatchUiState state)
    {
        _uuPatchStatusText = statusText;
        _uuPatchDetailText = detailText;
        _uuPatchUiState = state;
        RefreshUuPatchPresentation();
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

    private void RefreshUuPatchPresentation()
    {
        OnPropertyChanged(nameof(IsUuPatchActionEnabled));
        OnPropertyChanged(nameof(UuPatchStatusText));
        OnPropertyChanged(nameof(UuPatchDetailText));
        OnPropertyChanged(nameof(UuPatchBadgeBackground));
        OnPropertyChanged(nameof(UuPatchStatusForeground));
    }

    private static SolidColorBrush BrushFromHex(string value)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(value));
        brush.Freeze();
        return brush;
    }
}
