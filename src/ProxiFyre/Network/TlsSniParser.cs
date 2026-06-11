using System.Buffers.Binary;
using System.Text;

namespace ProxiFyre;

internal static class TlsSniParser
{
    public const int MaxProbeBytes = 16 * 1024;

    public static bool TryGetTlsServerName(ReadOnlySpan<byte> data, out string? serverName, out bool needMore)
    {
        serverName = null;
        needMore = false;

        if (data.Length < 5)
        {
            needMore = true;
            return false;
        }

        if (data[0] != 0x16 || data[1] != 0x03 || data[2] > 0x04)
        {
            return false;
        }

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(data[3..5]);
        if (recordLength == 0)
        {
            return false;
        }

        if (data.Length < 5 + recordLength)
        {
            needMore = data.Length < MaxProbeBytes;
            return false;
        }

        return TryGetTlsHandshakeServerName(data.Slice(5, recordLength), out serverName, out needMore);
    }

    public static bool TryGetDtlsServerName(ReadOnlySpan<byte> data, out string? serverName)
    {
        serverName = null;
        if (data.Length < 13)
        {
            return false;
        }

        if (data[0] != 0x16 || data[1] != 0xfe)
        {
            return false;
        }

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(data[11..13]);
        if (recordLength == 0 || data.Length < 13 + recordLength)
        {
            return false;
        }

        var record = data.Slice(13, recordLength);
        if (record.Length < 12 || record[0] != 0x01)
        {
            return false;
        }

        var fragmentOffset = ReadUInt24(record[6..9]);
        var fragmentLength = ReadUInt24(record[9..12]);
        if (fragmentOffset != 0 || fragmentLength == 0 || record.Length < 12 + fragmentLength)
        {
            return false;
        }

        return TryGetClientHelloBodyServerName(record.Slice(12, fragmentLength), isDtls: true, out serverName);
    }

    private static bool TryGetTlsHandshakeServerName(ReadOnlySpan<byte> record, out string? serverName, out bool needMore)
    {
        serverName = null;
        needMore = false;

        if (record.Length < 4)
        {
            needMore = true;
            return false;
        }

        if (record[0] != 0x01)
        {
            return false;
        }

        var handshakeLength = ReadUInt24(record[1..4]);
        if (handshakeLength == 0)
        {
            return false;
        }

        if (record.Length < 4 + handshakeLength)
        {
            needMore = true;
            return false;
        }

        return TryGetClientHelloBodyServerName(record.Slice(4, handshakeLength), isDtls: false, out serverName);
    }

    private static bool TryGetClientHelloBodyServerName(ReadOnlySpan<byte> body, bool isDtls, out string? serverName)
    {
        serverName = null;
        var offset = 2 + 32;
        if (!TrySkipVector8(body, ref offset))
        {
            return false;
        }

        if (isDtls && !TrySkipVector8(body, ref offset))
        {
            return false;
        }

        if (!TrySkipVector16(body, ref offset) || !TrySkipVector8(body, ref offset))
        {
            return false;
        }

        if (offset + 2 > body.Length)
        {
            return false;
        }

        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(offset, 2));
        offset += 2;
        if (offset + extensionsLength > body.Length)
        {
            return false;
        }

        var extensions = body.Slice(offset, extensionsLength);
        var extensionOffset = 0;
        while (extensionOffset + 4 <= extensions.Length)
        {
            var extensionType = BinaryPrimitives.ReadUInt16BigEndian(extensions.Slice(extensionOffset, 2));
            var extensionLength = BinaryPrimitives.ReadUInt16BigEndian(extensions.Slice(extensionOffset + 2, 2));
            extensionOffset += 4;
            if (extensionOffset + extensionLength > extensions.Length)
            {
                return false;
            }

            var extension = extensions.Slice(extensionOffset, extensionLength);
            if (extensionType == 0x0000 && TryGetServerNameFromExtension(extension, out serverName))
            {
                return true;
            }

            extensionOffset += extensionLength;
        }

        return false;
    }

    private static bool TryGetServerNameFromExtension(ReadOnlySpan<byte> extension, out string? serverName)
    {
        serverName = null;
        if (extension.Length < 2)
        {
            return false;
        }

        var listLength = BinaryPrimitives.ReadUInt16BigEndian(extension[..2]);
        var offset = 2;
        if (offset + listLength > extension.Length)
        {
            return false;
        }

        var listEnd = offset + listLength;
        while (offset + 3 <= listEnd)
        {
            var nameType = extension[offset];
            var nameLength = BinaryPrimitives.ReadUInt16BigEndian(extension.Slice(offset + 1, 2));
            offset += 3;
            if (offset + nameLength > listEnd)
            {
                return false;
            }

            if (nameType == 0)
            {
                var candidate = Encoding.ASCII.GetString(extension.Slice(offset, nameLength));
                if (IsPlausibleServerName(candidate))
                {
                    serverName = candidate;
                    return true;
                }
            }

            offset += nameLength;
        }

        return false;
    }

    private static bool TrySkipVector8(ReadOnlySpan<byte> data, ref int offset)
    {
        if (offset + 1 > data.Length)
        {
            return false;
        }

        var length = data[offset];
        offset++;
        if (offset + length > data.Length)
        {
            return false;
        }

        offset += length;
        return true;
    }

    private static bool TrySkipVector16(ReadOnlySpan<byte> data, ref int offset)
    {
        if (offset + 2 > data.Length)
        {
            return false;
        }

        var length = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
        offset += 2;
        if (offset + length > data.Length)
        {
            return false;
        }

        offset += length;
        return true;
    }

    private static int ReadUInt24(ReadOnlySpan<byte> data)
    {
        return (data[0] << 16) | (data[1] << 8) | data[2];
    }

    private static bool IsPlausibleServerName(string serverName)
    {
        if (serverName.Length is 0 or > 253)
        {
            return false;
        }

        foreach (var ch in serverName)
        {
            if (char.IsAsciiLetterOrDigit(ch) || ch is '-' or '.' or '_')
            {
                continue;
            }

            return false;
        }

        return serverName.Contains('.', StringComparison.Ordinal) && !serverName.Contains("..", StringComparison.Ordinal);
    }
}
