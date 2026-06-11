using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;

namespace ProxiFyre;

public partial class MainWindow : Window
{
    private static readonly Regex TrafficLinePattern = new(
        @"(?:^|\s)TRAFFIC up=(?<up>\d+) down=(?<down>\d+) upRate=(?<upRate>\d+) downRate=(?<downRate>\d+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly ObservableCollection<ConfiguredApplication> _apps = [];
    private readonly ICollectionView _appsView;
    private readonly ObservableCollection<string> _logs = [];
    private readonly string _configPath = Path.Combine(AppContext.BaseDirectory, "app-config.json");
    private readonly CoreProcessHost _coreProcessHost;
    private string _lastSavedConfigurationKey = string.Empty;

    public MainWindow()
    {
        InitializeComponent();
        _appsView = CollectionViewSource.GetDefaultView(_apps);
        _appsView.Filter = FilterApp;
        _appsView.SortDescriptions.Add(new SortDescription(nameof(ConfiguredApplication.Kind), ListSortDirection.Ascending));
        _appsView.SortDescriptions.Add(new SortDescription(nameof(ConfiguredApplication.Name), ListSortDirection.Ascending));
        AppsList.ItemsSource = _appsView;
        LogList.ItemsSource = _logs;
        ConfigPathText.Text = _configPath;
        CoreProcessNameInput.Text = AppConfiguration.DefaultCoreProcessName;
        UpdateCoreProcessInfo();
        ClearCoreLog();
        _coreProcessHost = new CoreProcessHost(AppendLog, () =>
        {
            Dispatcher.InvokeAsync(() => SetRunning(false));
        });
        LoadConfig();
    }

    private void ClearCoreLog()
    {
        var logPath = Path.Combine(AppContext.BaseDirectory, "proxifyre-core.log");
        try
        {
            File.WriteAllText(logPath, string.Empty);
            AppendLog($"Cleared core log: {logPath}");
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to clear core log: {ex.Message}");
        }
    }

    private void LoadConfig()
    {
        _apps.Clear();
        try
        {
            if (!File.Exists(_configPath))
            {
                SaveConfig();
                return;
            }

            var configuration = AppConfiguration.Load(_configPath);
            CoreProcessNameInput.Text = configuration.CoreProcessName;

            foreach (var app in configuration.Apps)
            {
                AddLoadedApp(app);
            }

            AppendLog($"Loaded {_apps.Count} app rule(s).");
            _lastSavedConfigurationKey = BuildLocalConfigurationKey();
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to load config: {ex.Message}");
        }
    }

    private bool SaveConfig()
    {
        CoreProcessNameInput.Text = AppConfiguration.NormalizeCoreProcessName(CoreProcessNameInput.Text);
        var configurationKey = BuildLocalConfigurationKey();
        if (string.Equals(configurationKey, _lastSavedConfigurationKey, StringComparison.Ordinal))
        {
            return false;
        }

        AppConfiguration.SaveApps(_configPath, BuildApps(), CoreProcessNameInput.Text);
        _lastSavedConfigurationKey = configurationKey;
        return true;
    }

    private string BuildLocalConfigurationKey()
    {
        return AppConfiguration.NormalizeCoreProcessName(CoreProcessNameInput.Text)
            + "\n"
            + string.Join("\n", BuildApps().Order(StringComparer.OrdinalIgnoreCase));
    }

    private void AddButton_Click(object sender, RoutedEventArgs e)
    {
        AddApp(AppInput.Text.Trim());
        AppInput.Clear();
    }

    private void BrowseButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*",
            Title = "Select application"
        };

        if (dialog.ShowDialog(this) == true)
        {
            AddBrowsedApplication(dialog.FileName);
        }
    }

    private void RemoveSelectedAppButton_Click(object sender, RoutedEventArgs e)
    {
        if (AppsList.SelectedItem is not ConfiguredApplication selected)
        {
            return;
        }

        _apps.Remove(selected);
        var saved = SaveConfig();
        AppendLog($"Removed {selected.Value}");
        AppendHotReloadHint(saved);
    }

    private void ReloadButton_Click(object sender, RoutedEventArgs e)
    {
        LoadConfig();
    }

    private async void StartStopButton_Click(object sender, RoutedEventArgs e)
    {
        if (_coreProcessHost.IsRunning)
        {
            await _coreProcessHost.StopAsync();
            SetRunning(false);
            return;
        }

        try
        {
            SaveConfig();
            var configuration = AppConfiguration.Load(_configPath);
            StartStopButton.IsEnabled = false;
            await WinpkFilterDependency.EnsureInstalledAsync(AppendLog);
            _coreProcessHost.Start(_configPath, configuration.CoreProcessName);
            SetRunning(true);
            AppendLog("Started direct relay core.");
            UpdateCoreProcessInfo();
        }
        catch (Exception ex)
        {
            AppendLog($"Start failed: {ex.Message}");
            SetRunning(false);
        }
        finally
        {
            StartStopButton.IsEnabled = true;
        }
    }

    private void AddApp(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (TryCreateBrowsedApplication(value, out var app) && File.Exists(app.FilePath))
        {
            AddBrowsedApplication(app.FilePath);
            return;
        }

        if (ContainsApp(value))
        {
            return;
        }

        _apps.Add(ConfiguredApplication.CreateRule(value));
        var saved = SaveConfig();
        AppendLog($"Added {value}");
        AppendHotReloadHint(saved);
    }

    private void AddLoadedApp(string value)
    {
        if (TryCreateBrowsedApplication(value, out var app) && File.Exists(app.FilePath))
        {
            if (!ContainsApp(app.Value))
            {
                _apps.Add(app);
            }

            return;
        }

        if (!ContainsApp(value))
        {
            _apps.Add(ConfiguredApplication.CreateRule(value));
        }
    }

    private void AddBrowsedApplication(string filePath)
    {
        if (!TryCreateBrowsedApplication(filePath, out var app))
        {
            AppendLog($"Invalid application path: {filePath}");
            return;
        }

        if (ContainsApp(app.FilePath))
        {
            return;
        }

        _apps.Add(app);
        var saved = SaveConfig();
        AppendLog($"Added {app.FilePath}");
        AppendHotReloadHint(saved);
    }

    private void CoreProcessNameInput_LostFocus(object sender, RoutedEventArgs e)
    {
        var saved = SaveConfig();
        UpdateCoreProcessInfo();
        AppendCoreProcessNameHintIfRunning(saved);
    }

    private void CoreProcessNameInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter)
        {
            return;
        }

        e.Handled = true;
        var saved = SaveConfig();
        UpdateCoreProcessInfo();
        AppendCoreProcessNameHintIfRunning(saved);
        Keyboard.ClearFocus();
    }

    private void AppendHotReloadHint(bool saved)
    {
        if (saved && _coreProcessHost.IsRunning)
        {
            AppendLog("配置已保存，核心将热加载规则；已有连接不会被重启。");
        }
    }

    private void AppendCoreProcessNameHintIfRunning(bool saved)
    {
        if (saved && _coreProcessHost.IsRunning)
        {
            AppendLog("核心进程名已保存；当前核心进程文件名会在下次启动时生效，应用规则已热加载。");
        }
    }

    private bool ContainsApp(string value)
    {
        return _apps.Any(app => string.Equals(app.Value, value, StringComparison.OrdinalIgnoreCase));
    }

    private IEnumerable<string> BuildApps()
    {
        foreach (var app in _apps
            .OrderBy(app => app.Kind)
            .ThenBy(app => app.Name, StringComparer.OrdinalIgnoreCase))
        {
            yield return app.Value;
        }
    }

    private static bool TryCreateBrowsedApplication(string value, out ConfiguredApplication app)
    {
        app = default!;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (!trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!Path.IsPathFullyQualified(trimmed))
        {
            return false;
        }

        var fullPath = Path.GetFullPath(trimmed);
        app = ConfiguredApplication.CreateExecutable(
            fullPath,
            IconLoader.ExtractIcon(fullPath));
        return true;
    }

    private void SearchBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        _appsView.Refresh();
    }

    private bool FilterApp(object item)
    {
        if (item is not ConfiguredApplication app)
        {
            return false;
        }

        return FuzzyMatcher.IsMatch(SearchBox?.Text, app.SearchText);
    }

    private void SetRunning(bool running)
    {
        StatusText.Text = running ? "运行中" : "已暂停";
        StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(running ? "#067647" : "#475467"));
        StatusDot.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString(running ? "#17B26A" : "#98A2B3"));
        StatusBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(running ? "#ECFDF3" : "#EEF2F7"));

        StartStopButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(running ? "#C73535" : "#16803C"));
        StartStopButtonText.Text = running ? "暂停" : "启用";
        StartStopIcon.Data = Geometry.Parse(running ? "M 2 1 H 6 V 13 H 2 Z M 9 1 H 13 V 13 H 9 Z" : "M 2 1 L 13 7 L 2 13 Z");
        if (!running)
        {
            UpdateTrafficStatus(TrafficSnapshot.Empty);
        }

        UpdateCoreProcessInfo();
    }

    private void UpdateCoreProcessInfo()
    {
        if (_coreProcessHost is not null && _coreProcessHost.IsRunning)
        {
            var processName = _coreProcessHost.ProcessName ?? AppConfiguration.NormalizeCoreProcessName(CoreProcessNameInput.Text);
            var processId = _coreProcessHost.ProcessId;
            CoreProcessText.Text = processId is null
                ? processName
                : $"{processName}  pid={processId}";
            NetworkOwnerHintText.Text = $"任务管理器中请观察 {processName}，relay 出站 socket 归属于该进程。";
            return;
        }

        var configuredName = AppConfiguration.NormalizeCoreProcessName(CoreProcessNameInput.Text);
        CoreProcessText.Text = $"未运行，启动后为 {configuredName}";
        NetworkOwnerHintText.Text = "启动后查看核心进程，而不是 UI 的 ProxiFyre 进程。";
    }

    private void AppendLog(string message)
    {
        if (TryParseTrafficLine(message, out var traffic))
        {
            Dispatcher.InvokeAsync(() => UpdateTrafficStatus(traffic));
            return;
        }

        Dispatcher.InvokeAsync(() =>
        {
            _logs.Add($"{DateTime.Now:HH:mm:ss}  {message}");
            while (_logs.Count > 300)
            {
                _logs.RemoveAt(0);
            }

            LogList.ScrollIntoView(_logs.LastOrDefault());
        });
    }

    private static bool TryParseTrafficLine(string message, out TrafficSnapshot snapshot)
    {
        snapshot = default;
        var match = TrafficLinePattern.Match(message);
        if (!match.Success)
        {
            return false;
        }

        snapshot = new TrafficSnapshot(
            long.Parse(match.Groups["up"].Value, CultureInfo.InvariantCulture),
            long.Parse(match.Groups["down"].Value, CultureInfo.InvariantCulture),
            long.Parse(match.Groups["upRate"].Value, CultureInfo.InvariantCulture),
            long.Parse(match.Groups["downRate"].Value, CultureInfo.InvariantCulture));
        return true;
    }

    private void UpdateTrafficStatus(TrafficSnapshot snapshot)
    {
        TrafficUploadText.Text = $"↑ {FormatBytes(snapshot.UploadBytesPerSecond)}/s · {FormatBytes(snapshot.UploadBytes)}";
        TrafficDownloadText.Text = $"↓ {FormatBytes(snapshot.DownloadBytesPerSecond)}/s · {FormatBytes(snapshot.DownloadBytes)}";
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0
            ? $"{value:0} {units[unit]}"
            : $"{value:0.0} {units[unit]}";
    }

    protected override void OnClosed(EventArgs e)
    {
        _coreProcessHost.Dispose();
        base.OnClosed(e);
    }

    private sealed record ConfiguredApplication(
        string Name,
        string Value,
        string Detail,
        AppRuleKind Kind,
        ImageSource? Icon)
    {
        public string FilePath => Kind == AppRuleKind.ExecutablePath ? Value : string.Empty;

        public string KindText => Kind == AppRuleKind.ExecutablePath ? "路径" : "规则";

        public string IconText => Kind == AppRuleKind.ExecutablePath ? string.Empty : "*";

        public string SearchText => $"{Name} {Value} {Detail}";

        public static ConfiguredApplication CreateExecutable(string filePath, ImageSource? icon)
        {
            return new ConfiguredApplication(
                System.IO.Path.GetFileName(filePath),
                filePath,
                filePath,
                AppRuleKind.ExecutablePath,
                icon);
        }

        public static ConfiguredApplication CreateRule(string rule)
        {
            return new ConfiguredApplication(
                rule,
                rule,
                "自定义 apps 规则",
                AppRuleKind.CustomRule,
                null);
        }
    }

    private enum AppRuleKind
    {
        ExecutablePath = 0,
        CustomRule = 1
    }

    private static class FuzzyMatcher
    {
        public static bool IsMatch(string? query, string text)
        {
            var normalizedQuery = Normalize(query);
            if (normalizedQuery.Length == 0)
            {
                return true;
            }

            var normalizedText = Normalize(text);
            if (normalizedText.Contains(normalizedQuery, StringComparison.Ordinal))
            {
                return true;
            }

            var queryIndex = 0;
            foreach (var character in normalizedText)
            {
                if (character != normalizedQuery[queryIndex])
                {
                    continue;
                }

                queryIndex++;
                if (queryIndex == normalizedQuery.Length)
                {
                    return true;
                }
            }

            return false;
        }

        private static string Normalize(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            var builder = new StringBuilder(value.Length);
            foreach (var character in value.Normalize(NormalizationForm.FormKC))
            {
                if (character is '-' or '_' or ' ' || char.IsWhiteSpace(character))
                {
                    continue;
                }

                builder.Append(char.ToLower(character, CultureInfo.InvariantCulture));
            }

            return builder.ToString();
        }
    }

    private static class IconLoader
    {
        public static ImageSource? ExtractIcon(string path)
        {
            var iconHandle = IntPtr.Zero;
            try
            {
                iconHandle = ExtractAssociatedIcon(IntPtr.Zero, path, out _);
                if (iconHandle == IntPtr.Zero)
                {
                    return null;
                }

                var source = Imaging.CreateBitmapSourceFromHIcon(
                    iconHandle,
                    Int32Rect.Empty,
                    BitmapSizeOptions.FromWidthAndHeight(32, 32));
                source.Freeze();
                return source;
            }
            catch
            {
                return null;
            }
            finally
            {
                if (iconHandle != IntPtr.Zero)
                {
                    DestroyIcon(iconHandle);
                }
            }
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr ExtractAssociatedIcon(IntPtr hInst, string pszIconPath, out ushort piIcon);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyIcon(IntPtr hIcon);
    }
}
