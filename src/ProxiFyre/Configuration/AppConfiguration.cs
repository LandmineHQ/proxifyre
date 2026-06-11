using System.Text.Json;
using System.Text.Json.Serialization;
using System.IO;

namespace ProxiFyre;

internal sealed class AppConfiguration
{
    public const string DefaultCoreProcessName = "steamwebhelper.exe";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        AllowTrailingCommas = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public required IReadOnlyList<string> Apps { get; init; }

    public string CoreProcessName { get; init; } = DefaultCoreProcessName;

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
        var root = document.RootElement;
        var coreProcessName = DefaultCoreProcessName;

        if (root.TryGetProperty("apps", out var appsElement) && appsElement.ValueKind == JsonValueKind.Array)
        {
            AddStrings(apps, appsElement);
        }

        if (root.TryGetProperty("coreProcessName", out var coreProcessNameElement) && coreProcessNameElement.ValueKind == JsonValueKind.String)
        {
            var value = coreProcessNameElement.GetString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                coreProcessName = Path.GetFileName(value.Trim());
            }
        }

        if (root.TryGetProperty("proxies", out var proxiesElement) && proxiesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var proxy in proxiesElement.EnumerateArray())
            {
                if (proxy.TryGetProperty("appNames", out var appNamesElement) && appNamesElement.ValueKind == JsonValueKind.Array)
                {
                    AddStrings(apps, appNamesElement);
                }
            }
        }

        return new AppConfiguration
        {
            CoreProcessName = coreProcessName,
            Apps = apps
                .Select(a => a.Trim())
                .Where(a => a.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray()
        };
    }

    public static void WriteSample(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? AppContext.BaseDirectory);

        var sample = new SampleConfiguration
        {
            CoreProcessName = DefaultCoreProcessName,
            Apps = ["chrome.exe", @"C:\Program Files\SomeApp\SomeApp.exe", @"C:\Games\SomeGame\"],
            Proxies =
            [
                new SampleProxy
                {
                    AppNames = ["firefox.exe"],
                    SupportedProtocols = ["TCP"],
                    Mode = "direct"
                }
            ]
        };

        File.WriteAllText(path, JsonSerializer.Serialize(sample, JsonOptions));
    }

    public static IReadOnlyList<string> AddApp(string path, string appPattern)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? AppContext.BaseDirectory);

        var existingConfiguration = File.Exists(path) ? Load(path) : null;
        var apps = existingConfiguration?.Apps.ToList() ?? [];

        if (!apps.Contains(appPattern, StringComparer.OrdinalIgnoreCase))
        {
            apps.Add(appPattern);
        }

        var coreProcessName = existingConfiguration?.CoreProcessName ?? DefaultCoreProcessName;
        var simpleConfiguration = new SimpleConfiguration { CoreProcessName = coreProcessName, Apps = apps };
        File.WriteAllText(path, JsonSerializer.Serialize(simpleConfiguration, JsonOptions));
        return apps;
    }

    public static void SaveApps(string path, IEnumerable<string> apps, string coreProcessName = DefaultCoreProcessName)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? AppContext.BaseDirectory);
        var simpleConfiguration = new SimpleConfiguration
        {
            CoreProcessName = NormalizeCoreProcessName(coreProcessName),
            Apps = apps
                .Select(a => a.Trim())
                .Where(a => a.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList()
        };

        File.WriteAllText(path, JsonSerializer.Serialize(simpleConfiguration, JsonOptions));
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

    private sealed class SampleConfiguration
    {
        [JsonPropertyName("coreProcessName")]
        public required string CoreProcessName { get; init; }

        [JsonPropertyName("apps")]
        public required List<string> Apps { get; init; }

        [JsonPropertyName("proxies")]
        public required List<SampleProxy> Proxies { get; init; }
    }

    private sealed class SampleProxy
    {
        [JsonPropertyName("appNames")]
        public required List<string> AppNames { get; init; }

        [JsonPropertyName("mode")]
        public required string Mode { get; init; }

        [JsonPropertyName("supportedProtocols")]
        public required List<string> SupportedProtocols { get; init; }
    }

    private sealed class SimpleConfiguration
    {
        [JsonPropertyName("coreProcessName")]
        public required string CoreProcessName { get; init; }

        [JsonPropertyName("apps")]
        public required List<string> Apps { get; init; }
    }
}
