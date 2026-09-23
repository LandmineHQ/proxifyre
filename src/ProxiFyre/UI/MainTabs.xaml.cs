using System.Windows.Controls;

namespace ProxiFyre;

public partial class MainTabs : UserControl
{
    public MainTabs()
    {
        InitializeComponent();
        ApplicationRulesTab.SearchChanged += (_, _) => SearchChanged?.Invoke(this, EventArgs.Empty);
        ApplicationRulesTab.EditAppRequested += (_, e) => EditAppRequested?.Invoke(this, e);
        ApplicationRulesTab.ToggleEnabledRequested += (_, e) => ToggleEnabledRequested?.Invoke(this, e);
        ApplicationRulesTab.RemoveAppRequested += (_, e) => RemoveAppRequested?.Invoke(this, e);
        RuntimeInfoTab.ReloadRequested += (_, _) => ReloadRequested?.Invoke(this, EventArgs.Empty);
        SettingsTab.UuPatchToggleRequested += (_, e) => UuPatchToggleRequested?.Invoke(this, e);
    }

    public event EventHandler? SearchChanged;

    public event EventHandler<ItemRequestedEventArgs>? EditAppRequested;

    public event EventHandler<ItemRequestedEventArgs>? ToggleEnabledRequested;

    public event EventHandler<ItemRequestedEventArgs>? RemoveAppRequested;

    public event EventHandler? ReloadRequested;

    public event EventHandler<UuPatchToggleRequestedEventArgs>? UuPatchToggleRequested;

    public ListBox Apps => ApplicationRulesTab.Apps;

    public ListBox Logs => LogsTab.Logs;

    public string SearchText => ApplicationRulesTab.SearchText;

    internal void SetSettingsViewModel(SettingsViewModel viewModel)
    {
        SettingsTab.DataContext = viewModel;
    }

    public void SetConfigPath(string configPath)
    {
        RuntimeInfoTab.SetConfigPath(configPath);
    }

    public void SetCoreProcessInfo(string text, string networkOwnerHint)
    {
        RuntimeInfoTab.SetCoreProcessInfo(text, networkOwnerHint);
    }

    public void SetLicenseKey(string? licenseKey)
    {
        RuntimeInfoTab.SetLicenseKey(licenseKey);
    }

    public void SetTrafficStatus(string uploadText, string downloadText, string? tooltip = null)
    {
        TrafficStatusBar.SetTrafficStatus(uploadText, downloadText, tooltip);
    }

    public void ScrollLogToEnd()
    {
        LogsTab.ScrollToEnd();
    }

}
