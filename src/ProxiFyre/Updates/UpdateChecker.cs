using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProxiFyre;

internal static class UpdateChecker
{
    public static string CurrentVersion => GetCurrentVersion();

    private const string ManifestUrl = "https://raw.githubusercontent.com/LandmineHQ/proxifyre/main/manifest.json";
    private const string GhProxyPrefix = "https://ghproxy.net/";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public static async Task<UpdateCheckResult> CheckAsync(Action<string>? log = null, CancellationToken cancellationToken = default)
    {
        var manifest = await FetchManifestAsync(log, cancellationToken).ConfigureAwait(false);
        if (manifest is null || string.IsNullOrWhiteSpace(manifest.Version))
        {
            return UpdateCheckResult.Failed(CurrentVersion, "无法获取更新清单，请检查网络连接或稍后再试。");
        }

        var latestVersion = manifest.Version.Trim();
        if (VersionsEqual(CurrentVersion, latestVersion))
        {
            return UpdateCheckResult.NoUpdate(CurrentVersion);
        }

        return UpdateCheckResult.UpdateAvailable(CurrentVersion, latestVersion, manifest.SourceUrl);
    }

    private static async Task<UpdateManifest?> FetchManifestAsync(Action<string>? log, CancellationToken cancellationToken)
    {
        var urls = new[] { ManifestUrl, GhProxyPrefix + ManifestUrl };
        Exception? lastError = null;
        for (var i = 0; i < urls.Length; i++)
        {
            var sourceName = i == 0 ? "GitHub" : "ghproxy";
            try
            {
                using var client = new HttpClient
                {
                    Timeout = TimeSpan.FromSeconds(8)
                };

                using var response = await client.GetAsync(urls[i], cancellationToken).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();

                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                var manifest = await JsonSerializer.DeserializeAsync<UpdateManifest>(stream, JsonOptions, cancellationToken).ConfigureAwait(false);
                log?.Invoke($"Update manifest loaded from {sourceName}.");
                return manifest;
            }
            catch (Exception ex) when (ex is HttpRequestException or JsonException
                || (ex is TaskCanceledException && !cancellationToken.IsCancellationRequested))
            {
                lastError = ex;
                log?.Invoke($"{sourceName} update manifest check failed: {ex.Message}");
                if (i + 1 < urls.Length)
                {
                    log?.Invoke("Retrying update manifest through ghproxy.");
                }
            }
        }

        log?.Invoke($"Update manifest unavailable: {lastError?.Message ?? "unknown error"}");
        return null;
    }

    private static bool VersionsEqual(string currentVersion, string latestVersion)
    {
        if (Version.TryParse(currentVersion, out var current) && Version.TryParse(latestVersion, out var latest))
        {
            return current.Equals(latest);
        }

        return string.Equals(
            NormalizeVersion(currentVersion),
            NormalizeVersion(latestVersion),
            StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeVersion(string value)
    {
        return value.Trim().TrimStart('v', 'V').Split('+', 2)[0];
    }

    private static string GetCurrentVersion()
    {
        var assembly = typeof(UpdateChecker).Assembly;
        var informationalVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informationalVersion))
        {
            return NormalizeVersion(informationalVersion);
        }

        return assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    }

    private sealed class UpdateManifest
    {
        [JsonPropertyName("version")]
        public string? Version { get; init; }

        [JsonPropertyName("sourceUrl")]
        public string? SourceUrl { get; init; }
    }
}

internal sealed record UpdateCheckResult(
    bool CheckFailed,
    bool HasUpdate,
    string CurrentVersion,
    string? LatestVersion,
    string? SourceUrl,
    string? ErrorMessage)
{
    public static UpdateCheckResult NoUpdate(string currentVersion)
    {
        return new UpdateCheckResult(false, false, currentVersion, null, null, null);
    }

    public static UpdateCheckResult UpdateAvailable(string currentVersion, string latestVersion, string? sourceUrl)
    {
        return new UpdateCheckResult(false, true, currentVersion, latestVersion, sourceUrl, null);
    }

    public static UpdateCheckResult Failed(string currentVersion, string errorMessage)
    {
        return new UpdateCheckResult(true, false, currentVersion, null, null, errorMessage);
    }
}
