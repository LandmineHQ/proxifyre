using System.Globalization;
using System.IO;
using System.Text.Json;

namespace ProxiFyre;

internal sealed class UuPatchTarget
{
    public required string Name { get; init; }

    public uint? Rva { get; init; }

    public UuBytePattern? Signature { get; init; }

    public int SignatureOffset { get; init; }

    public required byte[] OriginalBytes { get; init; }

    public required byte[] PatchedBytes { get; init; }
}

internal sealed class UuPatchProfile
{
    public required string Key { get; init; }

    public required string Label { get; init; }

    public required string Version { get; init; }

    public required string Sha256 { get; init; }

    public required string PatchedSha256 { get; init; }

    public required IReadOnlyList<UuPatchTarget> Targets { get; init; }
}

internal static class UuPatchCatalog
{
    public const string FileName = "UuPatchProfiles.json";

    public static IReadOnlyList<UuPatchProfile> LoadDefault()
    {
        return Load(Path.Combine(AppContext.BaseDirectory, FileName));
    }

    public static IReadOnlyList<UuPatchProfile> Load(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        if (!document.RootElement.TryGetProperty("profiles", out var profilesElement)
            || profilesElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"'{path}' does not contain a profiles array.");
        }

        var profiles = new List<UuPatchProfile>();
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var element in profilesElement.EnumerateArray())
        {
            var profile = ParseProfile(element);
            if (!keys.Add(profile.Key))
            {
                throw new InvalidDataException($"Duplicate UU patch profile key: {profile.Key}");
            }

            profiles.Add(profile);
        }

        return profiles;
    }

    public static UuPatchProfile? FindByHash(
        IEnumerable<UuPatchProfile> profiles,
        string sha256,
        bool allowPatchedHash)
    {
        return profiles.FirstOrDefault(profile =>
            string.Equals(profile.Sha256, sha256, StringComparison.OrdinalIgnoreCase)
            || (allowPatchedHash
                && string.Equals(profile.PatchedSha256, sha256, StringComparison.OrdinalIgnoreCase)));
    }

    private static UuPatchProfile ParseProfile(JsonElement element)
    {
        var key = GetRequiredString(element, "key");
        var targetsElement = element.TryGetProperty("targets", out var value)
            && value.ValueKind == JsonValueKind.Array
            ? value
            : throw new InvalidDataException($"UU patch profile '{key}' has no targets array.");

        var targets = new List<UuPatchTarget>();
        foreach (var targetElement in targetsElement.EnumerateArray())
        {
            var name = GetRequiredString(targetElement, "name");
            uint? rva = TryGetString(targetElement, "rva") is { } rvaText
                ? ParseRva(rvaText)
                : null;
            var signature = TryGetString(targetElement, "signature") is { } signatureText
                ? UuBytePattern.Parse(signatureText)
                : null;
            var signatureOffset = TryGetString(targetElement, "signatureOffset") is { } offsetText
                ? ParseInt32(offsetText)
                : 0;
            if (signature is null)
            {
                throw new InvalidDataException(
                    $"UU patch target '{key}/{name}' has no function signature.");
            }

            if (rva is null)
            {
                throw new InvalidDataException(
                    $"UU patch target '{key}/{name}' has no RVA fallback.");
            }

            var original = ParseBytes(GetRequiredString(targetElement, "original"));
            var patched = ParseBytes(GetRequiredString(targetElement, "patched"));
            if (original.Length == 0 || original.Length != patched.Length)
            {
                throw new InvalidDataException(
                    $"UU patch target '{key}/{name}' has invalid byte lengths.");
            }

            targets.Add(new UuPatchTarget
            {
                Name = name,
                Rva = rva,
                Signature = signature,
                SignatureOffset = signatureOffset,
                OriginalBytes = original,
                PatchedBytes = patched
            });
        }

        return new UuPatchProfile
        {
            Key = key,
            Label = GetRequiredString(element, "label"),
            Version = GetRequiredString(element, "version"),
            Sha256 = GetRequiredString(element, "sha256").ToUpperInvariant(),
            PatchedSha256 = GetRequiredString(element, "patchedSha256").ToUpperInvariant(),
            Targets = targets
        };
    }

    private static string GetRequiredString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(property.GetString()))
        {
            throw new InvalidDataException($"Missing UU patch profile property '{propertyName}'.");
        }

        return property.GetString()!.Trim();
    }

    private static string? TryGetString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        var value = property.GetString();
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static uint ParseRva(string value)
    {
        var text = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? value[2..]
            : value;
        return uint.Parse(text, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
    }

    private static int ParseInt32(string value)
    {
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return int.Parse(value[2..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
        }

        return int.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture);
    }

    private static byte[] ParseBytes(string value)
    {
        return value
            .Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(part => byte.Parse(part, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture))
            .ToArray();
    }
}
