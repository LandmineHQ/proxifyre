using System.Text;

namespace ProxiFyre;

internal static class ModuleMessageProtocol
{
    public const uint WmCopyData = 0x004A;
    public const int CommandDataId = 0x50584643;
    public const int EventDataId = 0x50584645;
    public const string WindowClassName = "ProxiFyre.Module.ControlWindow";
    public const string HookExportName = "ProxiFyre_GetMsgProc";

    public static string BuildCommand(
        string command,
        string? configPath = null,
        string? logPath = null,
        nint replyHwnd = 0,
        bool detailed = false)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["command"] = command,
            ["detailed"] = detailed ? "1" : "0"
        };

        if (!string.IsNullOrWhiteSpace(configPath))
        {
            values["configPath"] = configPath;
        }

        if (!string.IsNullOrWhiteSpace(logPath))
        {
            values["logPath"] = logPath;
        }

        if (replyHwnd != 0)
        {
            values["replyHwnd"] = replyHwnd.ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        return Serialize(values);
    }

    public static string BuildEvent(string eventName, string text, bool? running = null, int? pid = null)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["event"] = eventName,
            ["text64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(text))
        };

        if (running is not null)
        {
            values["running"] = running.Value ? "1" : "0";
        }

        if (pid is not null)
        {
            values["pid"] = pid.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        return Serialize(values);
    }

    public static bool TryParse(string payload, out Dictionary<string, string> values)
    {
        values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in payload.Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            if (trimmed.Length == 0)
            {
                continue;
            }

            var separator = trimmed.IndexOf('=');
            if (separator <= 0)
            {
                return false;
            }

            var key = trimmed[..separator];
            var value = trimmed[(separator + 1)..];
            values[key] = value;
        }

        return values.Count > 0;
    }

    public static string GetText(Dictionary<string, string> values)
    {
        if (!values.TryGetValue("text64", out var encoded) || string.IsNullOrWhiteSpace(encoded))
        {
            return values.TryGetValue("text", out var text) ? text : string.Empty;
        }

        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
        }
        catch
        {
            return string.Empty;
        }
    }

    public static nint GetReplyHwnd(Dictionary<string, string> values)
    {
        return values.TryGetValue("replyHwnd", out var raw)
            && long.TryParse(raw, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var handle)
            ? new nint(handle)
            : 0;
    }

    public static bool GetBool(Dictionary<string, string> values, string key)
    {
        return values.TryGetValue(key, out var raw)
            && (string.Equals(raw, "1", StringComparison.Ordinal)
                || string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase));
    }

    private static string Serialize(Dictionary<string, string> values)
    {
        var builder = new StringBuilder();
        foreach (var pair in values)
        {
            builder.Append(pair.Key);
            builder.Append('=');
            builder.Append(pair.Value.Replace('\r', ' ').Replace('\n', ' '));
            builder.Append('\n');
        }

        return builder.ToString();
    }
}
