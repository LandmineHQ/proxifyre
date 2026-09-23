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

    private bool _isUuPatchEnabled;
    private bool _isUuPatchBusy;
    private bool _isDetailedLoggingEnabled;
    private string _uuPatchBusyText = string.Empty;
    private string _uuPatchStatusText = "未检测";
    private string _uuPatchDetailText = "等待检测正在运行的 UU 应用。";
    private UuPatchUiState _uuPatchUiState = UuPatchUiState.Neutral;

    public bool IsUuPatchEnabled
    {
        get => _isUuPatchEnabled;
        set => SetProperty(ref _isUuPatchEnabled, value);
    }

    public bool IsDetailedLoggingEnabled
    {
        get => _isDetailedLoggingEnabled;
        set
        {
            if (SetProperty(ref _isDetailedLoggingEnabled, value))
            {
                OnPropertyChanged(nameof(DetailedLoggingStatusText));
            }
        }
    }

    public string DetailedLoggingStatusText => IsDetailedLoggingEnabled ? "已开启" : "已关闭";

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

    public void SetUuPatchEnabled(bool enabled)
    {
        IsUuPatchEnabled = enabled;
    }

    public void SetDetailedLoggingEnabled(bool enabled)
    {
        IsDetailedLoggingEnabled = enabled;
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
