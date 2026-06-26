using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
using Forms = System.Windows.Forms;

namespace ProxiFyre;

public partial class MainWindow : Window
{
    private const string DefaultSourceUrl = "https://github.com/LandmineHQ/proxifyre";
    private const int MaxUiLogEntries = 1000;
    private const int SwRestore = 9;

    private static readonly Regex TrafficLinePattern = new(
        @"(?:^|\s)TRAFFIC up=(?<up>\d+) down=(?<down>\d+) upRate=(?<upRate>\d+) downRate=(?<downRate>\d+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly ApplicationRulesManager _rulesManager = new();
    private readonly ObservableCollection<string> _logs = [];
    private readonly object _uiLogSync = new();
    private readonly ConfigurationStore _configurationStore = new(Path.Combine(AppContext.BaseDirectory, "app-config.json"));
    private readonly SettingsViewModel _settingsViewModel = new();
    private readonly WinpkFilterManager _winpkFilterManager;
    private readonly AotModuleController _moduleController;
    private readonly Forms.NotifyIcon _trayIcon;
    private readonly string _uiLogPath = Path.Combine(AppContext.BaseDirectory, "proxifyre-ui.log");
    private readonly StreamWriter _uiLogWriter;
    private bool _hasShownTrayHint;
    private bool _hasCheckedForUpdates;
    private bool _isAnnouncementDismissed;
    private string _sourceUrl = DefaultSourceUrl;

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(nint hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(nint hWnd, int nCmdShow);

    public MainWindow()
    {
        InitializeComponent();
        _uiLogWriter = CreateUiLogWriter(_uiLogPath);
        _trayIcon = CreateTrayIcon();
        Tabs.Apps.ItemsSource = _rulesManager.View;
        Tabs.Logs.ItemsSource = _logs;
        Tabs.SetSettingsViewModel(_settingsViewModel);
        Tabs.SetConfigPath(_configurationStore.Path);
        Tabs.SearchChanged += (_, _) => _rulesManager.SetSearchText(Tabs.SearchText);
        Tabs.EditAppRequested += Tabs_EditAppRequested;
        Tabs.RemoveAppRequested += Tabs_RemoveAppRequested;
        Tabs.ReloadRequested += (_, _) => ReloadConfigFromUi();
        Tabs.WinpkFilterActionRequested += Tabs_WinpkFilterActionRequested;
        Header.OpenSourceRequested += (_, _) => OpenSource();
        Header.StartStopRequested += Header_StartStopRequested;
        Announcement.DismissRequested += (_, _) => DismissAnnouncement();
        RuleEntry.AddRuleRequested += (_, e) => AddApp(e.Text);
        RuleEntry.BrowseApplicationRequested += (_, _) => BrowseApplication();
        RuleEntry.BrowseDirectoryRequested += (_, _) => BrowseDirectory();
        RuleEntry.CoreProcessNameChanged += (_, _) => SaveCoreProcessName();
        RuleEntry.CoreProcessName = AppConfiguration.DefaultCoreProcessName;
        _winpkFilterManager = new WinpkFilterManager(AppendLog);
        _winpkFilterManager.StatusChanged += WinpkFilterManager_StatusChanged;
        _moduleController = new AotModuleController(_configurationStore, _winpkFilterManager, AppendLog, moduleEvent =>
        {
            Dispatcher.InvokeAsync(() => ApplyModuleEvent(moduleEvent));
        });
        LoadLocalManifestInfo();
        SetVersionStatusChecking();
        UpdateCoreProcessInfo();
        RefreshSettingsInfo();
        ClearCoreLog();
        AppendLog($"UI log file: {_uiLogPath}");
        LoadConfig();
        Loaded += MainWindow_Loaded;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        await DiscoverExistingModuleAsync();

        if (_hasCheckedForUpdates)
        {
            return;
        }

        _hasCheckedForUpdates = true;
        await CheckForUpdatesAsync();
    }

    private async Task DiscoverExistingModuleAsync()
    {
        Header.StartStopEnabled = false;
        try
        {
            var result = await _moduleController.TryAttachExistingAsync(RuleEntry.CoreProcessName);
            switch (result)
            {
                case ModuleAttachResult.Attached:
                    AppendLog("已发现目标进程中的 AOT 模组，正在恢复 UI 连接。");
                    break;
                case ModuleAttachResult.TargetProcessMissing:
                    AppendLog($"未找到模组目标进程：{AppConfiguration.NormalizeCoreProcessName(RuleEntry.CoreProcessName)}。请先启动目标程序。");
                    MessageBox.Show(
                        this,
                        $"未找到模组目标进程：{AppConfiguration.NormalizeCoreProcessName(RuleEntry.CoreProcessName)}\n\n请先启动目标程序，然后再载入模组。",
                        "ProxiFyre",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    break;
                case ModuleAttachResult.NotLoaded:
                    AppendLog("目标进程已启动，但尚未发现 AOT 模组。");
                    break;
                case ModuleAttachResult.Unresponsive:
                    AppendLog("发现 AOT 模组窗口，但模组未响应心跳；点击载入模组前请确认目标进程状态。");
                    break;
            }
        }
        catch (Exception ex)
        {
            AppendLog($"Module reconnect failed: {ex.Message}");
        }
        finally
        {
            Header.StartStopEnabled = true;
            UpdateCoreProcessInfo();
        }
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
                ApplyManifestInfo(result.SourceUrl, result.Announcement);
                SetVersionStatusRemote(result.LatestVersion ?? result.CurrentVersion, hasUpdate: false);
                return;
            }

            ApplyManifestInfo(result.SourceUrl, result.Announcement);
            SetVersionStatusRemote(result.LatestVersion ?? "未知", hasUpdate: true);
            MessageBox.Show(
                this,
                $"发现新版本 {result.LatestVersion}\n当前版本：{result.CurrentVersion}\n\n请及时更新！",
                "ProxiFyre 更新提示",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AppendLog($"Update check failed: {ex.Message}");
        }
    }

    private void LoadLocalManifestInfo()
    {
        var manifestPath = Path.Combine(AppContext.BaseDirectory, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(manifestPath, Encoding.UTF8));
            var root = document.RootElement;
            var sourceUrl = TryGetManifestString(root, "sourceUrl");
            var announcement = TryGetManifestString(root, "announcement");
            ApplyManifestInfo(sourceUrl, announcement);
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to load local manifest: {ex.Message}");
        }
    }

    private static string? TryGetManifestString(JsonElement root, string propertyName)
    {
        return root.ValueKind == JsonValueKind.Object
            && root.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private void ApplyManifestInfo(string? sourceUrl, string? announcement)
    {
        var normalizedSourceUrl = NormalizeWebUrl(sourceUrl);
        if (normalizedSourceUrl is not null)
        {
            _sourceUrl = normalizedSourceUrl;
        }

        if (announcement is not null)
        {
            SetAnnouncement(announcement);
        }
    }

    private static string? NormalizeWebUrl(string? sourceUrl)
    {
        if (string.IsNullOrWhiteSpace(sourceUrl))
        {
            return null;
        }

        var trimmed = sourceUrl.Trim();
        return Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
            ? uri.AbsoluteUri
            : null;
    }

    private void SetAnnouncement(string? announcement)
    {
        var text = announcement?.Trim();
        if (_isAnnouncementDismissed || string.IsNullOrWhiteSpace(text))
        {
            Announcement.HideAnnouncement();
            return;
        }

        Announcement.ShowAnnouncement(text);
    }

    private void DismissAnnouncement()
    {
        _isAnnouncementDismissed = true;
        Announcement.HideAnnouncement();
    }

    private void SetVersionStatusChecking()
    {
        Header.SetVersionChecking(UpdateChecker.CurrentVersion);
    }

    private void SetVersionStatusRemote(string version, bool hasUpdate)
    {
        Header.SetRemoteVersion(version, hasUpdate);
    }

    private void SetVersionStatusFailed()
    {
        Header.SetVersionFailed();
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
        _rulesManager.Clear();
        try
        {
            var configuration = _configurationStore.LoadOrCreate(RuleEntry.CoreProcessName, _rulesManager.BuildApps());
            RuleEntry.CoreProcessName = configuration.CoreProcessName;
            _settingsViewModel.SetLicenseKey(configuration.LicenseKey);

            foreach (var app in configuration.Apps)
            {
                _rulesManager.AddLoadedRule(app);
            }

            AppendLog($"Loaded {_rulesManager.Rules.Count} app rule(s).");
            _configurationStore.MarkLoaded(RuleEntry.CoreProcessName, _rulesManager.BuildApps());
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to load config: {ex.Message}");
        }
    }

    private void ReloadConfigFromUi()
    {
        LoadConfig();
        if (_moduleController.IsRunning)
        {
            _moduleController.Reload();
            AppendLog("已向模组发送配置重载命令。");
        }
    }

    private bool SaveConfig()
    {
        RuleEntry.NormalizeCoreProcessName();
        return _configurationStore.Save(RuleEntry.CoreProcessName, _rulesManager.BuildApps());
    }

    private string? GetSavedLicenseKey()
    {
        return _configurationStore.GetLicenseKey();
    }

    private void RefreshSettingsInfo()
    {
        _settingsViewModel.SetLicenseKey(GetSavedLicenseKey());
        _settingsViewModel.ApplyWinpkFilterStatus(_winpkFilterManager.RefreshStatus());
    }

    private void WinpkFilterManager_StatusChanged(object? sender, WinpkFilterStatus status)
    {
        Dispatcher.InvokeAsync(() => _settingsViewModel.ApplyWinpkFilterStatus(status));
    }

    private void BrowseApplication()
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

    private void BrowseDirectory()
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

    private void Tabs_EditAppRequested(object? sender, ItemRequestedEventArgs e)
    {
        if (e.Item is ConfiguredApplication selected)
        {
            EditApplication(selected);
        }
    }

    private void EditApplication(ConfiguredApplication selected)
    {
        if (selected.Kind == ApplicationRuleKind.ExecutablePath)
        {
            ReselectApplicationPath(selected);
            return;
        }

        if (selected.Kind == ApplicationRuleKind.DirectoryPath)
        {
            ReselectDirectory(selected);
            return;
        }

        EditCustomRule(selected);
    }

    private void Tabs_RemoveAppRequested(object? sender, ItemRequestedEventArgs e)
    {
        if (e.Item is ConfiguredApplication selected)
        {
            RemoveApplication(selected);
        }
    }

    private async void Tabs_WinpkFilterActionRequested(object? sender, EventArgs e)
    {
        if (_moduleController.IsRunning)
        {
            MessageBox.Show(this, "请先停止模组转发，再修改 WinpkFilter 安装状态。", "ProxiFyre", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var status = _winpkFilterManager.RefreshStatus();
        if (status.IsInstalled)
        {
            var result = MessageBox.Show(
                this,
                "确定要卸载 WinpkFilter 吗？卸载后需要重新安装才能启用 relay。",
                "卸载 WinpkFilter",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (result != MessageBoxResult.Yes)
            {
                return;
            }
        }

        try
        {
            _settingsViewModel.SetWinpkFilterBusy(status.IsInstalled ? "正在卸载 WinpkFilter..." : "正在安装 WinpkFilter...");
            if (status.IsInstalled)
            {
                await _winpkFilterManager.UninstallAsync();
            }
            else
            {
                await _winpkFilterManager.EnsureInstalledAsync();
            }
        }
        catch (Exception ex)
        {
            AppendLog($"WinpkFilter action failed: {ex.Message}");
            MessageBox.Show(this, ex.Message, "WinpkFilter", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _settingsViewModel.ApplyWinpkFilterStatus(_winpkFilterManager.RefreshStatus());
            _settingsViewModel.SetWinpkFilterIdle();
        }
    }

    private void OpenSource()
    {
        try
        {
            Process.Start(new ProcessStartInfo(_sourceUrl)
            {
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to open source URL: {ex.Message}");
            MessageBox.Show(this, _sourceUrl, "GitHub", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private async void Header_StartStopRequested(object? sender, EventArgs e)
    {
        if (_moduleController.IsRunning)
        {
            _moduleController.StopRelay();
            SetRunning(false);
            return;
        }

        try
        {
            Header.StartStopEnabled = false;
            var result = await _moduleController.LoadAndRunAsync(
                RuleEntry.CoreProcessName,
                _rulesManager.BuildApps(),
                (deviceId, currentKey) => RegistrationDialog.Show(this, deviceId, currentKey));
            if (result == ModuleStartResult.Canceled)
            {
                return;
            }

            _settingsViewModel.SetLicenseKey(_configurationStore.GetLicenseKey());
            UpdateCoreProcessInfo();
        }
        catch (Exception ex)
        {
            AppendLog($"Module load failed: {ex.Message}");
            if (ex.Message.Contains("未找到模组目标进程", StringComparison.Ordinal))
            {
                MessageBox.Show(
                    this,
                    $"{ex.Message}\n\n请先启动目标程序，然后再载入模组。",
                    "ProxiFyre",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            else if (ex.Message.Contains("WH_GETMESSAGE", StringComparison.Ordinal))
            {
                MessageBox.Show(
                    this,
                    $"注入模组失败（未找到有效的消息循环或句柄）。\n\n请尝试将目标进程（{AppConfiguration.NormalizeCoreProcessName(RuleEntry.CoreProcessName)}）调至前台显示并处于活动状态，然后再尝试载入模组。",
                    "ProxiFyre 注入失败",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            else
            {
                MessageBox.Show(
                    this,
                    $"载入模组时发生错误：\n{ex.Message}",
                    "ProxiFyre 错误",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }

            SetRunning(false);
        }
        finally
        {
            Header.StartStopEnabled = true;
        }
    }

    private void AddApp(string value)
    {
        if (!_rulesManager.AddRule(value, out var app))
        {
            if (!string.IsNullOrWhiteSpace(value) && _rulesManager.Contains(value.Trim()))
            {
                ShowDuplicateRuleMessage(value.Trim());
            }

            return;
        }

        var saved = SaveConfig();
        AppendLog($"Added {app.Value}");
        AppendHotReloadHint(saved);
    }

    private void AddBrowsedApplication(string filePath)
    {
        if (!ApplicationRulesManager.TryCreateApplicationPath(filePath, out var app))
        {
            AppendLog($"Invalid application path: {filePath}");
            return;
        }

        if (!_rulesManager.AddApplicationPath(filePath, out app))
        {
            ShowDuplicateRuleMessage(app.FilePath);
            return;
        }

        var saved = SaveConfig();
        AppendLog($"Added {app.FilePath}");
        AppendHotReloadHint(saved);
    }

    private void AddBrowsedDirectory(string directoryPath)
    {
        if (!ApplicationRulesManager.TryCreateDirectoryPath(directoryPath, out var app))
        {
            AppendLog($"Invalid directory path: {directoryPath}");
            return;
        }

        if (!_rulesManager.AddDirectoryPath(directoryPath, out app))
        {
            ShowDuplicateRuleMessage(app.Value);
            return;
        }

        var saved = SaveConfig();
        AppendLog($"Added {app.Value}");
        AppendHotReloadHint(saved);
    }

    private void SaveCoreProcessName()
    {
        var saved = SaveConfig();
        UpdateCoreProcessInfo();
        AppendCoreProcessNameHintIfRunning(saved);
    }

    private void AppendHotReloadHint(bool saved)
    {
        if (saved && _moduleController.IsRunning)
        {
            _moduleController.Reload();
            AppendLog("配置已保存，已向模组发送重载命令；已有连接不会被重启。");
        }
    }

    private void AppendCoreProcessNameHintIfRunning(bool saved)
    {
        if (saved && _moduleController.IsRunning)
        {
            AppendLog("目标进程名已保存；已载入的 AOT 模组不会迁移进程，请在目标进程变更后重新载入。");
        }
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

        if (!ApplicationRulesManager.TryCreateApplicationPath(dialog.FileName, out var replacement))
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

        if (!ApplicationRulesManager.TryCreateDirectoryPath(dialog.FolderName, out var replacement))
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

        if (!ApplicationRulesManager.TryCreateApplication(updatedValue, out var replacement))
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

        if (_rulesManager.Contains(replacement.Value, selected))
        {
            ShowDuplicateRuleMessage(replacement.Value);
            return;
        }

        if (!_rulesManager.Replace(selected, replacement))
        {
            return;
        }

        var saved = SaveConfig();
        AppendLog($"Updated {selected.Value} -> {replacement.Value}");
        AppendHotReloadHint(saved);
    }

    private void RemoveApplication(ConfiguredApplication selected)
    {
        if (!_rulesManager.Remove(selected))
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

    private void SetRunning(bool running)
    {
        Header.SetRunning(running);
        if (!running)
        {
            UpdateTrafficStatus(TrafficSnapshot.Empty);
        }

        UpdateCoreProcessInfo();
    }

    private void UpdateCoreProcessInfo()
    {
        var info = _moduleController.GetDisplayInfo(RuleEntry.CoreProcessName);
        Tabs.SetCoreProcessInfo(info.Text, info.NetworkOwnerHint);
    }

    private void ApplyModuleEvent(ModuleEvent moduleEvent)
    {
        if (!string.IsNullOrWhiteSpace(moduleEvent.Text))
        {
            AppendLog($"module {moduleEvent.EventName}: {moduleEvent.Text}");
        }

        if (moduleEvent.Running is not null)
        {
            SetRunning(moduleEvent.Running.Value);
        }
        else
        {
            UpdateCoreProcessInfo();
        }
    }

    private void AppendLog(string message)
    {
        var uiLine = $"{DateTime.Now:HH:mm:ss}  {message}";
        WriteUiLogLine(message);

        if (TryParseTrafficLine(message, out var traffic))
        {
            Dispatcher.InvokeAsync(() => UpdateTrafficStatus(traffic));
            return;
        }

        Dispatcher.InvokeAsync(() =>
        {
            _logs.Add(uiLine);
            while (_logs.Count > MaxUiLogEntries)
            {
                _logs.RemoveAt(0);
            }

            Tabs.ScrollLogToEnd();
        });
    }

    private static StreamWriter CreateUiLogWriter(string logPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(logPath) ?? AppContext.BaseDirectory);
        var writer = new StreamWriter(new FileStream(logPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite))
        {
            AutoFlush = true
        };
        writer.WriteLine($"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} [INFO] UI log session started.");
        writer.WriteLine($"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} [INFO] Process: {Process.GetCurrentProcess().ProcessName} pid={Environment.ProcessId}");
        writer.WriteLine($"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} [INFO] Base directory: {AppContext.BaseDirectory}");
        writer.WriteLine($"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} [INFO] Log file: {logPath}");
        return writer;
    }

    private void WriteUiLogLine(string message)
    {
        lock (_uiLogSync)
        {
            try
            {
                _uiLogWriter.WriteLine($"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} [INFO] {message}");
            }
            catch
            {
            }
        }
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
        Tabs.SetTrafficStatus(
            $"↑ {FormatBytes(snapshot.UploadBytesPerSecond)}/s · {FormatBytes(snapshot.UploadBytes)}",
            $"↓ {FormatBytes(snapshot.DownloadBytesPerSecond)}/s · {FormatBytes(snapshot.DownloadBytes)}");
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
        _moduleController.Dispose();
        lock (_uiLogSync)
        {
            try
            {
                _uiLogWriter.WriteLine($"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} [INFO] UI log session ended.");
                _uiLogWriter.Dispose();
            }
            catch
            {
            }
        }

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

    public void ShowAndActivate()
    {
        if (WindowState == WindowState.Minimized || !ShowInTaskbar)
        {
            RestoreFromTray();
        }

        ShowInTaskbar = true;
        Show();
        WindowState = WindowState.Normal;

        var handle = new WindowInteropHelper(this).Handle;
        if (handle != nint.Zero)
        {
            ShowWindow(handle, SwRestore);
        }

        if (Topmost)
        {
            Activate();
            if (handle != nint.Zero)
            {
                SetForegroundWindow(handle);
            }

            return;
        }

        Topmost = true;
        Activate();
        Topmost = false;
        if (handle != nint.Zero)
        {
            SetForegroundWindow(handle);
        }
    }

}
