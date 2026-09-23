using System.IO;

namespace ProxiFyre;

internal sealed class ConfigurationStore
{
    private string _lastSavedKey = string.Empty;

    public ConfigurationStore(string path)
    {
        Path = path;
    }

    public string Path { get; }

    public AppConfiguration Load()
    {
        return AppConfiguration.Load(Path);
    }

    public AppConfiguration LoadOrCreate(
        string coreProcessName,
        IEnumerable<string> apps,
        IEnumerable<string>? disabledApps = null)
    {
        if (!File.Exists(Path))
        {
            Save(
                coreProcessName,
                apps,
                licenseKey: null,
                force: true,
                disabledApps: disabledApps);
        }

        return Load();
    }

    public string? GetLicenseKey()
    {
        try
        {
            return File.Exists(Path) ? Load().LicenseKey : null;
        }
        catch
        {
            return null;
        }
    }

    public bool GetUuWhitelistPatchEnabled()
    {
        try
        {
            return File.Exists(Path) && Load().EnableUuWhitelistPatch;
        }
        catch
        {
            return false;
        }
    }

    public bool GetDetailedLogging()
    {
        try
        {
            return File.Exists(Path) && Load().Detailed;
        }
        catch
        {
            return false;
        }
    }

    public bool Save(
        string coreProcessName,
        IEnumerable<string> apps,
        string? licenseKey = null,
        bool force = false,
        IEnumerable<string>? disabledApps = null)
    {
        var normalizedCoreProcessName = AppConfiguration.NormalizeCoreProcessName(coreProcessName);
        var appList = apps
            .Select(app => app.Trim())
            .Where(app => app.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var disabledAppList = (disabledApps ?? (File.Exists(Path) ? Load().DisabledApps : []))
            .Select(app => app.Trim())
            .Where(app => app.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var key = BuildKey(normalizedCoreProcessName, appList, disabledAppList);
        if (!force && string.Equals(key, _lastSavedKey, StringComparison.Ordinal))
        {
            return false;
        }

        AppConfiguration.SaveApps(
            Path,
            appList,
            normalizedCoreProcessName,
            licenseKey ?? GetLicenseKey(),
            disabledApps: disabledAppList);
        _lastSavedKey = key;
        return true;
    }

    public void SaveLicenseKey(
        string coreProcessName,
        IEnumerable<string> apps,
        string licenseKey,
        IEnumerable<string>? disabledApps = null)
    {
        var normalizedCoreProcessName = AppConfiguration.NormalizeCoreProcessName(coreProcessName);
        var appList = apps
            .Select(app => app.Trim())
            .Where(app => app.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var disabledAppList = (disabledApps ?? Load().DisabledApps)
            .Select(app => app.Trim())
            .Where(app => app.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        AppConfiguration.SaveApps(
            Path,
            appList,
            normalizedCoreProcessName,
            licenseKey,
            disabledApps: disabledAppList);
        _lastSavedKey = BuildKey(normalizedCoreProcessName, appList, disabledAppList);
    }

    public void SaveUuWhitelistPatch(bool enabled)
    {
        var configuration = Load();
        AppConfiguration.SaveApps(
            Path,
            configuration.Apps,
            configuration.CoreProcessName,
            configuration.LicenseKey,
            enabled,
            configuration.DisabledApps);
    }

    public void SaveDetailedLogging(bool enabled)
    {
        var configuration = Load();
        AppConfiguration.SaveApps(
            Path,
            configuration.Apps,
            configuration.CoreProcessName,
            configuration.LicenseKey,
            configuration.EnableUuWhitelistPatch,
            configuration.DisabledApps,
            enabled);
    }

    public void MarkLoaded(
        string coreProcessName,
        IEnumerable<string> apps,
        IEnumerable<string>? disabledApps = null)
    {
        _lastSavedKey = BuildKey(
            AppConfiguration.NormalizeCoreProcessName(coreProcessName),
            apps,
            disabledApps ?? []);
    }

    private static string BuildKey(
        string coreProcessName,
        IEnumerable<string> apps,
        IEnumerable<string> disabledApps)
    {
        return coreProcessName
            + "\n"
            + string.Join("\n", apps.Order(StringComparer.OrdinalIgnoreCase))
            + "\n--disabled--\n"
            + string.Join("\n", disabledApps.Order(StringComparer.OrdinalIgnoreCase));
    }
}
