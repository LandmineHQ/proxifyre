using System.Buffers.Binary;
using System.Globalization;
using System.IO;

namespace ProxiFyre;

internal sealed class UuBytePattern
{
    private UuBytePattern(byte[] values, byte[] masks)
    {
        Values = values;
        Masks = masks;
    }

    public byte[] Values { get; }

    public byte[] Masks { get; }

    public int Length => Values.Length;

    public static UuBytePattern Parse(string text)
    {
        var tokens = text.Split(
            [' ', '\t', '\r', '\n'],
            StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0)
        {
            throw new InvalidDataException("UU byte signature is empty.");
        }

        var values = new byte[tokens.Length];
        var masks = new byte[tokens.Length];
        for (var index = 0; index < tokens.Length; index++)
        {
            var token = tokens[index];
            if (token == "??")
            {
                continue;
            }

            if (token.Length != 2
                || !byte.TryParse(
                    token,
                    NumberStyles.AllowHexSpecifier,
                    CultureInfo.InvariantCulture,
                    out values[index]))
            {
                throw new InvalidDataException(
                    $"UU byte signature contains an invalid token: '{token}'.");
            }

            masks[index] = 0xFF;
        }

        return new UuBytePattern(values, masks);
    }

    public bool Matches(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Length)
        {
            return false;
        }

        for (var index = 0; index < Length; index++)
        {
            if ((bytes[index] & Masks[index]) != (Values[index] & Masks[index]))
            {
                return false;
            }
        }

        return true;
    }
}

internal sealed record UuResolvedPatchTarget(UuPatchTarget Target, uint Rva);

internal sealed class UuPeImage
{
    private readonly byte[] _bytes;
    private readonly IReadOnlyList<UuPeSection> _sections;

    private UuPeImage(byte[] bytes, IReadOnlyList<UuPeSection> sections)
    {
        _bytes = bytes;
        _sections = sections;
    }

    public static UuPeImage Load(string path)
    {
        var bytes = File.ReadAllBytes(path);
        return new UuPeImage(bytes, ParseSections(bytes));
    }

    public bool TryFindUniquePattern(
        UuBytePattern pattern,
        out uint rva,
        out string? error)
    {
        var matchCount = 0;
        rva = 0;
        foreach (var section in _sections)
        {
            var data = _bytes.AsSpan(
                checked((int)section.RawOffset),
                checked((int)Math.Min(section.RawSize, (uint)(_bytes.Length - section.RawOffset))));
            for (var offset = 0; offset + pattern.Length <= data.Length; offset++)
            {
                if (!pattern.Matches(data.Slice(offset, pattern.Length)))
                {
                    continue;
                }

                matchCount++;
                if (matchCount > 1)
                {
                    error = "signature matched more than one executable location";
                    return false;
                }

                rva = section.VirtualAddress + (uint)offset;
            }
        }

        if (matchCount == 0)
        {
            error = "signature was not found in an executable section";
            return false;
        }

        error = null;
        return true;
    }

    public bool BytesMatch(uint rva, ReadOnlySpan<byte> expected)
    {
        if (!TryResolveFileOffset(rva, out var fileOffset)
            || fileOffset + expected.Length > _bytes.Length)
        {
            return false;
        }

        return _bytes.AsSpan(fileOffset, expected.Length).SequenceEqual(expected);
    }

    private bool TryResolveFileOffset(uint rva, out int fileOffset)
    {
        foreach (var section in _sections)
        {
            var sectionSize = Math.Max(section.VirtualSize, section.RawSize);
            if (rva < section.VirtualAddress
                || rva >= section.VirtualAddress + sectionSize
                || rva - section.VirtualAddress >= section.RawSize)
            {
                continue;
            }

            var offset = (long)section.RawOffset + rva - section.VirtualAddress;
            if (offset >= 0 && offset < _bytes.Length)
            {
                fileOffset = (int)offset;
                return true;
            }
        }

        fileOffset = 0;
        return false;
    }

    private static IReadOnlyList<UuPeSection> ParseSections(byte[] bytes)
    {
        if (bytes.Length < 0x40
            || bytes[0] != (byte)'M'
            || bytes[1] != (byte)'Z')
        {
            throw new InvalidDataException("UU module is not a valid PE image.");
        }

        var peOffset = ReadUInt32(bytes, 0x3C);
        if (peOffset + 0x18 > bytes.Length
            || ReadUInt32(bytes, checked((int)peOffset)) != 0x00004550)
        {
            throw new InvalidDataException("UU module has an invalid PE signature.");
        }

        var sectionCount = ReadUInt16(bytes, checked((int)peOffset + 0x06));
        var optionalHeaderSize = ReadUInt16(bytes, checked((int)peOffset + 0x14));
        var sectionTable = checked((int)peOffset + 0x18 + optionalHeaderSize);
        var sections = new List<UuPeSection>(sectionCount);
        for (var index = 0; index < sectionCount; index++)
        {
            var offset = sectionTable + index * 0x28;
            if (offset + 0x28 > bytes.Length)
            {
                throw new InvalidDataException("UU module has a truncated section table.");
            }

            var name = System.Text.Encoding.ASCII
                .GetString(bytes, offset, 8)
                .TrimEnd('\0');
            var virtualSize = ReadUInt32(bytes, offset + 0x08);
            var virtualAddress = ReadUInt32(bytes, offset + 0x0C);
            var rawSize = ReadUInt32(bytes, offset + 0x10);
            var rawOffset = ReadUInt32(bytes, offset + 0x14);
            var characteristics = ReadUInt32(bytes, offset + 0x24);
            if (rawOffset >= bytes.Length)
            {
                continue;
            }

            if ((characteristics & 0x20000000) == 0
                && !name.Equals(".text", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            sections.Add(new UuPeSection(
                name,
                virtualAddress,
                virtualSize,
                rawOffset,
                Math.Min(rawSize, (uint)(bytes.Length - rawOffset)),
                characteristics));
        }

        if (sections.Count == 0)
        {
            throw new InvalidDataException("UU module has no executable sections.");
        }

        return sections;
    }

    private static ushort ReadUInt16(byte[] bytes, int offset)
    {
        return BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
    }

    private static uint ReadUInt32(byte[] bytes, int offset)
    {
        return BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
    }

    private sealed record UuPeSection(
        string Name,
        uint VirtualAddress,
        uint VirtualSize,
        uint RawOffset,
        uint RawSize,
        uint Characteristics);
}

internal static class UuPatchLocator
{
    public static bool TryResolve(
        IReadOnlyList<UuPatchProfile> profiles,
        string modulePath,
        string fileHash,
        out UuPatchProfile? profile,
        out IReadOnlyList<UuResolvedPatchTarget> targets,
        out string? error)
    {
        profile = null;
        targets = [];
        error = null;

        UuPeImage image;
        try
        {
            image = UuPeImage.Load(modulePath);
        }
        catch (Exception ex)
        {
            error = $"无法解析 local_proxy.dll 的 PE 结构：{ex.Message}";
            return false;
        }

        var exact = UuPatchCatalog.FindByHash(profiles, fileHash, allowPatchedHash: true);
        if (exact is not null)
        {
            if (!TryResolveProfile(exact, image, allowRvaFallback: true, out targets, out error))
            {
                return false;
            }

            profile = exact;
            return true;
        }

        var candidates = new List<UuPatchProfile>();
        foreach (var candidate in profiles)
        {
            if (candidate.Targets.Any(target => target.Signature is null))
            {
                continue;
            }

            if (TryResolveProfile(
                    candidate,
                    image,
                    allowRvaFallback: false,
                    out _,
                    out _))
            {
                candidates.Add(candidate);
            }
        }

        if (candidates.Count == 0)
        {
            error = $"未找到匹配的 local_proxy.dll 版本或函数签名：{fileHash}";
            return false;
        }

        if (candidates.Count > 1)
        {
            error =
                $"多个 UU 补丁 profile 的函数签名同时匹配：{string.Join(", ", candidates.Select(candidate => candidate.Key))}";
            return false;
        }

        profile = candidates[0];
        return TryResolveProfile(
            profile,
            image,
            allowRvaFallback: false,
            out targets,
            out error);
    }

    private static bool TryResolveProfile(
        UuPatchProfile profile,
        UuPeImage image,
        bool allowRvaFallback,
        out IReadOnlyList<UuResolvedPatchTarget> targets,
        out string? error)
    {
        var resolved = new List<UuResolvedPatchTarget>(profile.Targets.Count);
        foreach (var target in profile.Targets)
        {
            uint rva;
            if (target.Signature is not null)
            {
                if (!image.TryFindUniquePattern(target.Signature, out var matchRva, out var signatureError))
                {
                    if (!allowRvaFallback || target.Rva is null)
                    {
                        error = $"{profile.Key}/{target.Name}: {signatureError}";
                        targets = [];
                        return false;
                    }

                    rva = target.Rva.Value;
                }
                else
                {
                    var offset = (long)matchRva + target.SignatureOffset;
                    if (offset < 0 || offset > uint.MaxValue)
                    {
                        error = $"{profile.Key}/{target.Name}: signature offset is outside the image";
                        targets = [];
                        return false;
                    }

                    rva = (uint)offset;
                }
            }
            else if (allowRvaFallback && target.Rva is not null)
            {
                rva = target.Rva.Value;
            }
            else
            {
                error = $"{profile.Key}/{target.Name}: no usable function signature";
                targets = [];
                return false;
            }

            if (!image.BytesMatch(rva, target.OriginalBytes)
                && !image.BytesMatch(rva, target.PatchedBytes))
            {
                error =
                    $"{profile.Key}/{target.Name}: resolved bytes are neither the known original nor patched bytes";
                targets = [];
                return false;
            }

            resolved.Add(new UuResolvedPatchTarget(target, rva));
        }

        targets = resolved;
        error = null;
        return true;
    }
}
