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

    public AppConfiguration LoadOrCreate(string coreProcessName, IEnumerable<string> apps)
    {
        if (!File.Exists(Path))
        {
            Save(coreProcessName, apps, licenseKey: null, force: true);
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

    public bool Save(string coreProcessName, IEnumerable<string> apps, string? licenseKey = null, bool force = false)
    {
        var normalizedCoreProcessName = AppConfiguration.NormalizeCoreProcessName(coreProcessName);
        var appList = apps
            .Select(app => app.Trim())
            .Where(app => app.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var key = BuildKey(normalizedCoreProcessName, appList);
        if (!force && string.Equals(key, _lastSavedKey, StringComparison.Ordinal))
        {
            return false;
        }

        AppConfiguration.SaveApps(Path, appList, normalizedCoreProcessName, licenseKey ?? GetLicenseKey());
        _lastSavedKey = key;
        return true;
    }

    public void SaveLicenseKey(string coreProcessName, IEnumerable<string> apps, string licenseKey)
    {
        var normalizedCoreProcessName = AppConfiguration.NormalizeCoreProcessName(coreProcessName);
        var appList = apps
            .Select(app => app.Trim())
            .Where(app => app.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        AppConfiguration.SaveApps(Path, appList, normalizedCoreProcessName, licenseKey);
        _lastSavedKey = BuildKey(normalizedCoreProcessName, appList);
    }

    public void MarkLoaded(string coreProcessName, IEnumerable<string> apps)
    {
        _lastSavedKey = BuildKey(AppConfiguration.NormalizeCoreProcessName(coreProcessName), apps);
    }

    private static string BuildKey(string coreProcessName, IEnumerable<string> apps)
    {
        return coreProcessName
            + "\n"
            + string.Join("\n", apps.Order(StringComparer.OrdinalIgnoreCase));
    }
}
