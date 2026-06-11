using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using Forms = System.Windows.Forms;

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
    private readonly Forms.NotifyIcon _trayIcon;
    private string _lastSavedConfigurationKey = string.Empty;
    private bool _hasShownTrayHint;
    private bool _hasCheckedForUpdates;

    public MainWindow()
    {
        InitializeComponent();
        _trayIcon = CreateTrayIcon();
        _appsView = CollectionViewSource.GetDefaultView(_apps);
        _appsView.Filter = FilterApp;
        _appsView.SortDescriptions.Add(new SortDescription(nameof(ConfiguredApplication.Kind), ListSortDirection.Ascending));
        _appsView.SortDescriptions.Add(new SortDescription(nameof(ConfiguredApplication.Name), ListSortDirection.Ascending));
        AppsList.ItemsSource = _appsView;
        LogList.ItemsSource = _logs;
        ConfigPathText.Text = _configPath;
        CoreProcessNameInput.Text = AppConfiguration.DefaultCoreProcessName;
        SetVersionStatusChecking();
        UpdateCoreProcessInfo();
        ClearCoreLog();
        _coreProcessHost = new CoreProcessHost(AppendLog, () =>
        {
            Dispatcher.InvokeAsync(() => SetRunning(false));
        });
        LoadConfig();
        Loaded += MainWindow_Loaded;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        if (_hasCheckedForUpdates)
        {
            return;
        }

        _hasCheckedForUpdates = true;
        await CheckForUpdatesAsync();
    }

    private async Task CheckForUpdatesAsync()
    {
        try
        {
            var result = await UpdateChecker.CheckAsync(AppendLog);
            if (result.CheckFailed)
            {
                SetVersionStatusFailed();
                MessageBox.Show(
                    this,
                    $"{result.ErrorMessage}\n\n这不会影响当前版本继续使用。",
                    "ProxiFyre 更新检查失败",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            if (!result.HasUpdate)
            {
                SetVersionStatusRemote(result.LatestVersion ?? result.CurrentVersion, hasUpdate: false);
                return;
            }

            SetVersionStatusRemote(result.LatestVersion ?? "未知", hasUpdate: true);
            MessageBox.Show(
                this,
                $"发现新版本 {result.LatestVersion}。\n当前版本：{result.CurrentVersion}\n\n请从仓库获取最新源码或构建产物。",
                "ProxiFyre 更新提示",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AppendLog($"Update check failed: {ex.Message}");
        }
    }

    private void SetVersionStatusChecking()
    {
        LocalVersionText.Text = UpdateChecker.CurrentVersion;
        RemoteVersionText.Text = "检查中";
        RemoteVersionText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#667085"));
    }

    private void SetVersionStatusRemote(string version, bool hasUpdate)
    {
        RemoteVersionText.Text = version;
        RemoteVersionText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hasUpdate ? "#B54708" : "#067647"));
    }

    private void SetVersionStatusFailed()
    {
        RemoteVersionText.Text = "获取失败";
        RemoteVersionText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#C73535"));
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

        AppConfiguration.SaveApps(_configPath, BuildApps(), CoreProcessNameInput.Text, GetSavedLicenseKey());
        _lastSavedConfigurationKey = configurationKey;
        return true;
    }

    private string? GetSavedLicenseKey()
    {
        try
        {
            return File.Exists(_configPath)
                ? AppConfiguration.Load(_configPath).LicenseKey
                : null;
        }
        catch
        {
            return null;
        }
    }

    private void SaveLicenseKey(string licenseKey)
    {
        CoreProcessNameInput.Text = AppConfiguration.NormalizeCoreProcessName(CoreProcessNameInput.Text);
        AppConfiguration.SaveApps(_configPath, BuildApps(), CoreProcessNameInput.Text, licenseKey);
        _lastSavedConfigurationKey = BuildLocalConfigurationKey();
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
            Title = "选择应用"
        };

        if (dialog.ShowDialog(this) == true)
        {
            AddBrowsedApplication(dialog.FileName);
        }
    }

    private void BrowseDirectoryButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "选择目录"
        };

        if (dialog.ShowDialog(this) == true)
        {
            AddBrowsedDirectory(dialog.FolderName);
        }
    }

    private void EditAppButton_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not ConfiguredApplication selected)
        {
            return;
        }

        if (selected.Kind == AppRuleKind.ExecutablePath)
        {
            ReselectApplicationPath(selected);
            return;
        }

        if (selected.Kind == AppRuleKind.DirectoryPath)
        {
            ReselectDirectory(selected);
            return;
        }

        EditCustomRule(selected);
    }

    private void RemoveAppButton_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is ConfiguredApplication selected)
        {
            RemoveApplication(selected);
        }
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
            var deviceId = LicenseKey.GetCurrentDeviceId();
            if (!LicenseKey.IsValid(deviceId, configuration.LicenseKey))
            {
                var licenseKey = RegistrationDialog.Show(this, deviceId, configuration.LicenseKey);
                if (licenseKey is null)
                {
                    AppendLog("Start canceled: license key is missing or invalid.");
                    return;
                }

                SaveLicenseKey(licenseKey);
                configuration = AppConfiguration.Load(_configPath);
                AppendLog("License key saved.");
            }

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

        if (!TryCreateApplicationFromInput(value, out var app))
        {
            return;
        }

        if (ContainsApp(app.Value))
        {
            ShowDuplicateRuleMessage(app.Value);
            return;
        }

        _apps.Add(app);
        var saved = SaveConfig();
        AppendLog($"Added {app.Value}");
        AppendHotReloadHint(saved);
    }

    private void AddLoadedApp(string value)
    {
        if (TryCreateBrowsedApplication(value, out var app))
        {
            if (!ContainsApp(app.Value))
            {
                _apps.Add(app);
            }

            return;
        }

        if (TryCreateDirectoryApplication(value, out app))
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
            ShowDuplicateRuleMessage(app.FilePath);
            return;
        }

        _apps.Add(app);
        var saved = SaveConfig();
        AppendLog($"Added {app.FilePath}");
        AppendHotReloadHint(saved);
    }

    private void AddBrowsedDirectory(string directoryPath)
    {
        if (!TryCreateDirectoryApplication(directoryPath, out var app))
        {
            AppendLog($"Invalid directory path: {directoryPath}");
            return;
        }

        if (ContainsApp(app.Value))
        {
            ShowDuplicateRuleMessage(app.Value);
            return;
        }

        _apps.Add(app);
        var saved = SaveConfig();
        AppendLog($"Added {app.Value}");
        AppendHotReloadHint(saved);
    }

    private void CoreProcessNameInput_LostFocus(object sender, RoutedEventArgs e)
    {
        var saved = SaveConfig();
        UpdateCoreProcessInfo();
        AppendCoreProcessNameHintIfRunning(saved);
    }

    private void CoreProcessNameInput_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
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
        return ContainsApp(value, except: null);
    }

    private bool ContainsApp(string value, ConfiguredApplication? except)
    {
        return _apps.Any(app =>
            !ReferenceEquals(app, except)
            && string.Equals(app.Value, value, StringComparison.OrdinalIgnoreCase));
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

    private static bool TryCreateApplicationFromInput(string value, out ConfiguredApplication app)
    {
        app = default!;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (TryCreateBrowsedApplication(trimmed, out app))
        {
            return true;
        }

        if (TryCreateDirectoryApplication(trimmed, out app))
        {
            return true;
        }

        app = ConfiguredApplication.CreateRule(trimmed);
        return true;
    }

    private static bool TryCreateDirectoryApplication(string value, out ConfiguredApplication app)
    {
        app = default!;
        if (!ProcessMatcher.TryNormalizeDirectoryPattern(value, out var directoryPath))
        {
            return false;
        }

        app = ConfiguredApplication.CreateDirectory(directoryPath);
        return true;
    }

    private void ReselectApplicationPath(ConfiguredApplication selected)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*",
            Title = "重选应用"
        };

        var directory = Path.GetDirectoryName(selected.FilePath);
        if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory))
        {
            dialog.InitialDirectory = directory;
        }

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        if (!TryCreateBrowsedApplication(dialog.FileName, out var replacement))
        {
            AppendLog($"Invalid application path: {dialog.FileName}");
            return;
        }

        ReplaceApplication(selected, replacement);
    }

    private void ReselectDirectory(ConfiguredApplication selected)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "重选目录"
        };

        if (Directory.Exists(selected.DirectoryPath))
        {
            dialog.InitialDirectory = selected.DirectoryPath;
        }

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        if (!TryCreateDirectoryApplication(dialog.FolderName, out var replacement))
        {
            AppendLog($"Invalid directory path: {dialog.FolderName}");
            return;
        }

        ReplaceApplication(selected, replacement);
    }

    private void EditCustomRule(ConfiguredApplication selected)
    {
        var updatedValue = RuleEditDialog.Show(this, selected.Value);
        if (updatedValue is null)
        {
            return;
        }

        if (!TryCreateApplicationFromInput(updatedValue, out var replacement))
        {
            return;
        }

        ReplaceApplication(selected, replacement);
    }

    private void ReplaceApplication(ConfiguredApplication selected, ConfiguredApplication replacement)
    {
        if (string.Equals(selected.Value, replacement.Value, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (ContainsApp(replacement.Value, selected))
        {
            ShowDuplicateRuleMessage(replacement.Value);
            return;
        }

        var index = _apps.IndexOf(selected);
        if (index < 0)
        {
            return;
        }

        _apps[index] = replacement;
        _appsView.Refresh();
        var saved = SaveConfig();
        AppendLog($"Updated {selected.Value} -> {replacement.Value}");
        AppendHotReloadHint(saved);
    }

    private void RemoveApplication(ConfiguredApplication selected)
    {
        if (!_apps.Remove(selected))
        {
            return;
        }

        var saved = SaveConfig();
        AppendLog($"Removed {selected.Value}");
        AppendHotReloadHint(saved);
    }

    private void ShowDuplicateRuleMessage(string value)
    {
        MessageBox.Show(this, $"规则已存在：{value}", "ProxiFyre", MessageBoxButton.OK, MessageBoxImage.Information);
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

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        if (WindowState == WindowState.Minimized)
        {
            MinimizeToTray();
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        _coreProcessHost.Dispose();
        base.OnClosed(e);
    }

    private Forms.NotifyIcon CreateTrayIcon()
    {
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("显示窗口", null, (_, _) => Dispatcher.Invoke(RestoreFromTray));
        menu.Items.Add("退出", null, (_, _) => Dispatcher.Invoke(Close));

        var trayIcon = new Forms.NotifyIcon
        {
            Icon = LoadTrayIcon(),
            Text = "ProxiFyre Direct Relay",
            ContextMenuStrip = menu,
            Visible = false
        };
        trayIcon.DoubleClick += (_, _) => Dispatcher.Invoke(RestoreFromTray);
        return trayIcon;
    }

    private static System.Drawing.Icon LoadTrayIcon()
    {
        var resource = System.Windows.Application.GetResourceStream(new Uri("pack://application:,,,/Assets/AppIcon.ico", UriKind.Absolute));
        if (resource?.Stream is not null)
        {
            using var stream = resource.Stream;
            return new System.Drawing.Icon(stream);
        }

        return System.Drawing.SystemIcons.Application;
    }

    private void MinimizeToTray()
    {
        Hide();
        ShowInTaskbar = false;
        _trayIcon.Visible = true;
        if (!_hasShownTrayHint)
        {
            _hasShownTrayHint = true;
            _trayIcon.ShowBalloonTip(1200, "ProxiFyre", "已最小化到托盘。双击图标可恢复窗口。", Forms.ToolTipIcon.Info);
        }
    }

    private void RestoreFromTray()
    {
        _trayIcon.Visible = false;
        ShowInTaskbar = true;
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private sealed record ConfiguredApplication(
        string Name,
        string Value,
        string Detail,
        AppRuleKind Kind,
        ImageSource? Icon)
    {
        public string FilePath => Kind == AppRuleKind.ExecutablePath ? Value : string.Empty;

        public string DirectoryPath => Kind == AppRuleKind.DirectoryPath ? Value : string.Empty;

        public string KindText => Kind switch
        {
            AppRuleKind.ExecutablePath => "应用",
            AppRuleKind.DirectoryPath => "目录",
            _ => "规则"
        };

        public string PrimaryActionText => Kind == AppRuleKind.CustomRule ? "编辑" : "重选";

        public string IconText => Kind switch
        {
            AppRuleKind.ExecutablePath => string.Empty,
            AppRuleKind.DirectoryPath => "D",
            _ => "*"
        };

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

        public static ConfiguredApplication CreateDirectory(string directoryPath)
        {
            var normalized = ProcessMatcher.TryNormalizeDirectoryPattern(directoryPath, out var normalizedDirectory)
                ? normalizedDirectory
                : directoryPath;
            var trimmed = Path.TrimEndingDirectorySeparator(normalized);
            var name = Path.GetFileName(trimmed);
            if (string.IsNullOrWhiteSpace(name))
            {
                name = normalized;
            }

            return new ConfiguredApplication(
                name,
                normalized,
                normalized,
                AppRuleKind.DirectoryPath,
                null);
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
        DirectoryPath = 1,
        CustomRule = 2
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

    private sealed class RegistrationDialog : Window
    {
        private readonly string _deviceId;
        private readonly System.Windows.Controls.TextBox _keyInput;

        private RegistrationDialog(string deviceId, string? currentKey)
        {
            _deviceId = deviceId;
            Title = "注册 ProxiFyre";
            Owner = System.Windows.Application.Current.MainWindow;
            Width = 520;
            MinWidth = 460;
            MinHeight = 300;
            SizeToContent = SizeToContent.Height;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F3F6FA"));

            var root = new Grid
            {
                Margin = new Thickness(18)
            };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var title = new TextBlock
            {
                Text = "需要注册后才能启用核心",
                FontSize = 16,
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#111827"))
            };
            root.Children.Add(title);

            var subtitle = new TextBlock
            {
                Text = "请复制当前设备码，并输入对应注册码。",
                Margin = new Thickness(0, 6, 0, 16),
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#667085"))
            };
            Grid.SetRow(subtitle, 1);
            root.Children.Add(subtitle);

            var deviceLabel = new TextBlock
            {
                Text = "当前设备码",
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1F2937"))
            };
            Grid.SetRow(deviceLabel, 2);
            root.Children.Add(deviceLabel);

            var deviceRow = new Grid
            {
                Margin = new Thickness(0, 8, 0, 14)
            };
            deviceRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            deviceRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var deviceInput = new System.Windows.Controls.TextBox
            {
                Text = deviceId,
                IsReadOnly = true,
                MinHeight = 34,
                Padding = new Thickness(9, 6, 9, 6),
                VerticalContentAlignment = VerticalAlignment.Center
            };
            deviceRow.Children.Add(deviceInput);

            var copyButton = new Button
            {
                Content = "复制",
                MinWidth = 72,
                Margin = new Thickness(8, 0, 0, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EEF2F7")),
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1F2937"))
            };
            copyButton.Click += (_, _) =>
            {
                Clipboard.SetText(_deviceId);
                copyButton.Content = "已复制";
            };
            Grid.SetColumn(copyButton, 1);
            deviceRow.Children.Add(copyButton);

            Grid.SetRow(deviceRow, 3);
            root.Children.Add(deviceRow);

            var keyLabel = new TextBlock
            {
                Text = "注册码",
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1F2937"))
            };
            Grid.SetRow(keyLabel, 4);
            root.Children.Add(keyLabel);

            var keyArea = new StackPanel
            {
                Margin = new Thickness(0, 8, 0, 0)
            };

            _keyInput = new System.Windows.Controls.TextBox
            {
                Text = currentKey ?? string.Empty,
                MinHeight = 34,
                Padding = new Thickness(9, 6, 9, 6),
                VerticalContentAlignment = VerticalAlignment.Center
            };
            _keyInput.SelectAll();
            _keyInput.KeyDown += Input_KeyDown;
            keyArea.Children.Add(_keyInput);

            var buttons = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 16, 0, 0)
            };

            var cancel = new Button
            {
                Content = "取消",
                MinWidth = 72,
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EEF2F7")),
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1F2937")),
                Margin = new Thickness(0, 0, 8, 0)
            };
            cancel.Click += (_, _) => DialogResult = false;
            buttons.Children.Add(cancel);

            var confirm = new Button
            {
                Content = "确定",
                MinWidth = 72,
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2563EB")),
                Foreground = Brushes.White
            };
            confirm.Click += (_, _) => Confirm();
            buttons.Children.Add(confirm);
            keyArea.Children.Add(buttons);

            Grid.SetRow(keyArea, 5);
            root.Children.Add(keyArea);

            Content = root;
            Loaded += (_, _) => _keyInput.Focus();
        }

        public string KeyText => _keyInput.Text.Trim();

        public static string? Show(Window owner, string deviceId, string? currentKey)
        {
            var dialog = new RegistrationDialog(deviceId, currentKey)
            {
                Owner = owner
            };

            return dialog.ShowDialog() == true
                ? dialog.KeyText
                : null;
        }

        private void Input_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                e.Handled = true;
                Confirm();
            }
        }

        private void Confirm()
        {
            if (!LicenseKey.IsValid(_deviceId, _keyInput.Text))
            {
                MessageBox.Show(this, "注册码无效。", "ProxiFyre", MessageBoxButton.OK, MessageBoxImage.Warning);
                _keyInput.Focus();
                _keyInput.SelectAll();
                return;
            }

            DialogResult = true;
        }
    }

    private sealed class RuleEditDialog : Window
    {
        private readonly System.Windows.Controls.TextBox _input;

        private RuleEditDialog(string currentValue)
        {
            Title = "编辑应用规则";
            Owner = System.Windows.Application.Current.MainWindow;
            Width = 460;
            MinHeight = 210;
            MinWidth = 420;
            SizeToContent = SizeToContent.Height;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F3F6FA"));

            var root = new Grid
            {
                Margin = new Thickness(16)
            };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var label = new TextBlock
            {
                Text = "应用规则",
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1F2937"))
            };
            root.Children.Add(label);

            _input = new System.Windows.Controls.TextBox
            {
                Text = currentValue,
                MinHeight = 32,
                Margin = new Thickness(0, 8, 0, 6),
                Padding = new Thickness(9, 5, 9, 5),
                VerticalContentAlignment = VerticalAlignment.Center
            };
            _input.SelectAll();
            _input.KeyDown += Input_KeyDown;
            Grid.SetRow(_input, 1);
            root.Children.Add(_input);

            var hint = new TextBlock
            {
                Text = "例如 chrome.exe、完整 exe 路径，或目录路径。",
                FontSize = 12,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#667085"))
            };
            Grid.SetRow(hint, 2);
            root.Children.Add(hint);

            var buttons = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 14, 0, 0)
            };

            var cancel = new Button
            {
                Content = "取消",
                MinWidth = 72,
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EEF2F7")),
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1F2937")),
                Margin = new Thickness(0, 0, 8, 0)
            };
            cancel.Click += (_, _) => DialogResult = false;
            buttons.Children.Add(cancel);

            var confirm = new Button
            {
                Content = "保存",
                MinWidth = 72,
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2563EB")),
                Foreground = Brushes.White
            };
            confirm.Click += (_, _) => Confirm();
            buttons.Children.Add(confirm);

            Grid.SetRow(buttons, 3);
            root.Children.Add(buttons);

            Content = root;
            Loaded += (_, _) => _input.Focus();
        }

        public string RuleText => _input.Text.Trim();

        public static string? Show(Window owner, string currentValue)
        {
            var dialog = new RuleEditDialog(currentValue)
            {
                Owner = owner
            };

            return dialog.ShowDialog() == true
                ? dialog.RuleText
                : null;
        }

        private void Input_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                e.Handled = true;
                Confirm();
            }
        }

        private void Confirm()
        {
            if (string.IsNullOrWhiteSpace(_input.Text))
            {
                MessageBox.Show(this, "请输入应用规则。", "ProxiFyre", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            DialogResult = true;
        }
    }
}
