using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace ProxiFyre;

internal static class LicenseKey
{
    private const string DeviceSalt = "ProxiFyre.DeviceId.v1|x5pB7cQ9nR2w";
    private const string KeySalt = "ProxiFyre.LicenseKey.v1|hB4jK2sN8uQ6";
    private const string MachineGuidRegistryPath = @"SOFTWARE\Microsoft\Cryptography";

    public static string GetCurrentDeviceId()
    {
        return CreateDeviceId(ReadMachineFingerprint());
    }

    public static string CreateKey(string deviceId)
    {
        var normalizedDeviceId = NormalizeDeviceId(deviceId);
        if (normalizedDeviceId.Length == 0)
        {
            throw new ArgumentException("Device id cannot be empty.", nameof(deviceId));
        }

        var hash = Sha256($"{KeySalt}|{normalizedDeviceId}");
        return FormatGroups(ToBase32(hash, 26), 5);
    }

    public static bool IsValid(string? deviceId, string? key)
    {
        if (string.IsNullOrWhiteSpace(deviceId) || string.IsNullOrWhiteSpace(key))
        {
            return false;
        }

        var expected = NormalizeKey(CreateKey(deviceId));
        var actual = NormalizeKey(key);
        return actual.Length > 0
            && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(actual));
    }

    public static string NormalizeKey(string? key)
    {
        return NormalizeCode(key);
    }

    public static string NormalizeDeviceId(string? deviceId)
    {
        return NormalizeCode(deviceId);
    }

    private static string ReadMachineFingerprint()
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(MachineGuidRegistryPath);
                var machineGuid = key?.GetValue("MachineGuid") as string;
                if (!string.IsNullOrWhiteSpace(machineGuid))
                {
                    return "MachineGuid:" + machineGuid.Trim();
                }
            }
            catch
            {
            }
        }

        return "MachineName:" + Environment.MachineName;
    }

    private static string CreateDeviceId(string fingerprint)
    {
        var hash = Sha256($"{DeviceSalt}|{fingerprint}");
        return FormatGroups(ToBase32(hash, 20), 4);
    }

    private static byte[] Sha256(string value)
    {
        return SHA256.HashData(Encoding.UTF8.GetBytes(value));
    }

    private static string NormalizeCode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(value.Length);
        foreach (var character in value.Normalize(NormalizationForm.FormKC))
        {
            if (char.IsLetterOrDigit(character))
            {
                builder.Append(char.ToUpperInvariant(character));
            }
        }

        return builder.ToString();
    }

    private static string FormatGroups(string value, int groupSize)
    {
        var builder = new StringBuilder(value.Length + value.Length / groupSize);
        for (var i = 0; i < value.Length; i++)
        {
            if (i > 0 && i % groupSize == 0)
            {
                builder.Append('-');
            }

            builder.Append(value[i]);
        }

        return builder.ToString();
    }

    private static string ToBase32(ReadOnlySpan<byte> bytes, int outputLength)
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        var builder = new StringBuilder(outputLength);
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var current in bytes)
        {
            buffer = (buffer << 8) | current;
            bitsLeft += 8;
            while (bitsLeft >= 5 && builder.Length < outputLength)
            {
                var index = (buffer >> (bitsLeft - 5)) & 31;
                builder.Append(alphabet[index]);
                bitsLeft -= 5;
            }

            if (builder.Length == outputLength)
            {
                break;
            }
        }

        return builder.ToString();
    }
}
