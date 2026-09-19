using System.Text.Json;
using System.Text.Json.Serialization;
using System.IO;

namespace ProxiFyre;

internal sealed class AppConfiguration
{
    public const string DefaultCoreProcessName = "steamwebhelper.exe";

    public required IReadOnlyList<string> Apps { get; init; }

    public IReadOnlyList<string> DisabledApps { get; init; } = [];

    public string CoreProcessName { get; init; } = DefaultCoreProcessName;

    public string? LicenseKey { get; init; }

    public bool EnableFakeIpWhitelist { get; init; } = false;

    public bool EnableUuWhitelistPatch { get; init; } = false;

    public string ModuleDllName { get; init; } = "ProxiFyre.Module.dll";

    public bool Matches(ProcessInfo process)
    {
        return TryGetMatchingPattern(process, out _, out _);
    }

    public bool TryGetMatchingPattern(ProcessInfo process, out string? pattern, out string? reason)
    {
        if (process.Name.Equals(CoreProcessName, StringComparison.OrdinalIgnoreCase))
        {
            pattern = null;
            reason = $"process is configured core process '{CoreProcessName}'";
            return false;
        }

        foreach (var appPattern in Apps)
        {
            if (ProcessMatcher.IsMatch(appPattern, process))
            {
                pattern = appPattern;
                reason = null;
                return true;
            }
        }

        pattern = null;
        reason = "no configured app pattern matched";
        return false;
    }

    public static AppConfiguration Load(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Configuration file was not found.", path);
        }

        using var document = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip
        });

        var apps = new List<string>();
        var disabledApps = new List<string>();
        var root = document.RootElement;
        var coreProcessName = DefaultCoreProcessName;
        string? licenseKey = null;

        if (root.TryGetProperty("apps", out var appsElement) && appsElement.ValueKind == JsonValueKind.Array)
        {
            AddStrings(apps, appsElement);
        }

        if (root.TryGetProperty("disabledApps", out var disabledAppsElement)
            && disabledAppsElement.ValueKind == JsonValueKind.Array)
        {
            AddStrings(disabledApps, disabledAppsElement);
        }

        if (root.TryGetProperty("coreProcessName", out var coreProcessNameElement) && coreProcessNameElement.ValueKind == JsonValueKind.String)
        {
            var value = coreProcessNameElement.GetString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                coreProcessName = Path.GetFileName(value.Trim());
            }
        }

        if (root.TryGetProperty("licenseKey", out var licenseKeyElement) && licenseKeyElement.ValueKind == JsonValueKind.String)
        {
            licenseKey = licenseKeyElement.GetString();
        }

        bool enableFakeIpWhitelist = false;
        if (root.TryGetProperty("enableFakeIpWhitelist", out var enableFakeIpWhitelistElement))
        {
            if (enableFakeIpWhitelistElement.ValueKind == JsonValueKind.True)
            {
                enableFakeIpWhitelist = true;
            }
        }

        string? moduleDllName = null;
        if (root.TryGetProperty("moduleDllName", out var moduleDllNameElement) && moduleDllNameElement.ValueKind == JsonValueKind.String)
        {
            moduleDllName = moduleDllNameElement.GetString();
        }

        bool enableUuWhitelistPatch = false;
        if (root.TryGetProperty("enableUuWhitelistPatch", out var enableUuWhitelistPatchElement))
        {
            if (enableUuWhitelistPatchElement.ValueKind == JsonValueKind.True)
            {
                enableUuWhitelistPatch = true;
            }
        }

        var enabledApps = apps
            .Select(app => app.Trim())
            .Where(app => app.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var disabledAppList = disabledApps
            .Select(app => app.Trim())
            .Where(app => app.Length > 0)
            .Where(app => !enabledApps.Contains(app, StringComparer.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new AppConfiguration
        {
            CoreProcessName = coreProcessName,
            LicenseKey = string.IsNullOrWhiteSpace(licenseKey) ? null : licenseKey.Trim(),
            EnableFakeIpWhitelist = enableFakeIpWhitelist,
            EnableUuWhitelistPatch = enableUuWhitelistPatch,
            ModuleDllName = string.IsNullOrWhiteSpace(moduleDllName) ? "ProxiFyre.Module.dll" : moduleDllName.Trim(),
            Apps = enabledApps,
            DisabledApps = disabledAppList
        };
    }

    public static void WriteSample(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? AppContext.BaseDirectory);

        var sample = new SampleConfiguration
        {
            CoreProcessName = DefaultCoreProcessName,
            LicenseKey = string.Empty,
            Apps = ["chrome.exe", @"C:\Program Files\SomeApp\SomeApp.exe", @"C:\Games\SomeGame\"],
            DisabledApps = [],
            EnableUuWhitelistPatch = false,
            ModuleDllName = "ProxiFyre.Module.dll"
        };

        File.WriteAllText(path, JsonSerializer.Serialize(sample, AppConfigurationJsonContext.Default.SampleConfiguration));
    }

    public static IReadOnlyList<string> AddApp(string path, string appPattern)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? AppContext.BaseDirectory);

        var existingConfiguration = File.Exists(path) ? Load(path) : null;
        var apps = existingConfiguration?.Apps.ToList() ?? [];
        var disabledApps = existingConfiguration?.DisabledApps.ToList() ?? [];

        if (!apps.Contains(appPattern, StringComparer.OrdinalIgnoreCase))
        {
            apps.Add(appPattern);
        }
        disabledApps.RemoveAll(app => string.Equals(app, appPattern, StringComparison.OrdinalIgnoreCase));

        var coreProcessName = existingConfiguration?.CoreProcessName ?? DefaultCoreProcessName;
        var simpleConfiguration = new SimpleConfiguration
        {
            CoreProcessName = coreProcessName,
            LicenseKey = existingConfiguration?.LicenseKey,
            Apps = apps,
            DisabledApps = disabledApps,
            EnableFakeIpWhitelist = existingConfiguration?.EnableFakeIpWhitelist ?? false,
            EnableUuWhitelistPatch = existingConfiguration?.EnableUuWhitelistPatch ?? false,
            ModuleDllName = existingConfiguration?.ModuleDllName ?? "ProxiFyre.Module.dll"
        };
        File.WriteAllText(path, JsonSerializer.Serialize(simpleConfiguration, AppConfigurationJsonContext.Default.SimpleConfiguration));
        return apps;
    }

    public static void SaveApps(
        string path,
        IEnumerable<string> apps,
        string coreProcessName = DefaultCoreProcessName,
        string? licenseKey = null,
        bool? enableUuWhitelistPatch = null,
        IEnumerable<string>? disabledApps = null)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? AppContext.BaseDirectory);
        var existing = File.Exists(path) ? Load(path) : null;
        var simpleConfiguration = new SimpleConfiguration
        {
            CoreProcessName = NormalizeCoreProcessName(coreProcessName),
            LicenseKey = string.IsNullOrWhiteSpace(licenseKey) ? null : licenseKey.Trim(),
            Apps = apps
                .Select(a => a.Trim())
                .Where(a => a.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            DisabledApps = (disabledApps ?? existing?.DisabledApps ?? [])
                .Select(a => a.Trim())
                .Where(a => a.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            EnableFakeIpWhitelist = existing?.EnableFakeIpWhitelist ?? false,
            EnableUuWhitelistPatch = enableUuWhitelistPatch
                ?? existing?.EnableUuWhitelistPatch
                ?? false,
            ModuleDllName = existing?.ModuleDllName ?? "ProxiFyre.Module.dll"
        };

        File.WriteAllText(path, JsonSerializer.Serialize(simpleConfiguration, AppConfigurationJsonContext.Default.SimpleConfiguration));
    }

    public static string NormalizeCoreProcessName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return DefaultCoreProcessName;
        }

        var name = Path.GetFileName(value.Trim());
        return string.IsNullOrWhiteSpace(name) ? DefaultCoreProcessName : name;
    }

    private static void AddStrings(List<string> apps, JsonElement element)
    {
        foreach (var item in element.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String)
            {
                var value = item.GetString();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    apps.Add(value);
                }
            }
        }
    }

    internal sealed class SampleConfiguration
    {
        [JsonPropertyName("coreProcessName")]
        public required string CoreProcessName { get; init; }

        [JsonPropertyName("licenseKey")]
        public string? LicenseKey { get; init; }

        [JsonPropertyName("apps")]
        public required List<string> Apps { get; init; }

        [JsonPropertyName("disabledApps")]
        public required List<string> DisabledApps { get; init; }

        [JsonPropertyName("enableUuWhitelistPatch")]
        public bool EnableUuWhitelistPatch { get; init; }

        [JsonPropertyName("moduleDllName")]
        public string? ModuleDllName { get; init; }

    }

    internal sealed class SimpleConfiguration
    {
        [JsonPropertyName("coreProcessName")]
        public required string CoreProcessName { get; init; }

        [JsonPropertyName("licenseKey")]
        public string? LicenseKey { get; init; }

        [JsonPropertyName("apps")]
        public required List<string> Apps { get; init; }

        [JsonPropertyName("disabledApps")]
        public required List<string> DisabledApps { get; init; }

        [JsonPropertyName("enableFakeIpWhitelist")]
        public bool EnableFakeIpWhitelist { get; init; }

        [JsonPropertyName("enableUuWhitelistPatch")]
        public bool EnableUuWhitelistPatch { get; init; }

        [JsonPropertyName("moduleDllName")]
        public string? ModuleDllName { get; init; }
    }
}

[JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AppConfiguration.SampleConfiguration))]
[JsonSerializable(typeof(AppConfiguration.SimpleConfiguration))]
internal sealed partial class AppConfigurationJsonContext : JsonSerializerContext
{
}
