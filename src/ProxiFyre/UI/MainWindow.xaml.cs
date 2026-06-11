using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;

namespace ProxiFyre;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ConfiguredApplication> _apps = [];
    private readonly ICollectionView _appsView;
    private readonly ObservableCollection<string> _logs = [];
    private readonly string _configPath = Path.Combine(AppContext.BaseDirectory, "app-config.json");
    private readonly CoreProcessHost _coreProcessHost;

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
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to load config: {ex.Message}");
        }
    }

    private void SaveConfig()
    {
        AppConfiguration.SaveApps(_configPath, BuildApps(), CoreProcessNameInput.Text);
        CoreProcessNameInput.Text = AppConfiguration.NormalizeCoreProcessName(CoreProcessNameInput.Text);
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
        SaveConfig();
        AppendLog($"Removed {selected.Value}");
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
        SaveConfig();
        AppendLog($"Added {value}");
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
        SaveConfig();
        AppendLog($"Added {app.FilePath}");
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
