using System.IO;
using System.Windows.Media;

namespace ProxiFyre;

internal sealed record ConfiguredApplication(
    string Name,
    string Value,
    string Detail,
    ApplicationRuleKind Kind,
    ImageSource? Icon)
{
    public string FilePath => Kind == ApplicationRuleKind.ExecutablePath ? Value : string.Empty;

    public string DirectoryPath => Kind == ApplicationRuleKind.DirectoryPath ? Value : string.Empty;

    public string KindText => Kind switch
    {
        ApplicationRuleKind.ExecutablePath => "应用",
        ApplicationRuleKind.DirectoryPath => "目录",
        _ => "规则"
    };

    public string PrimaryActionText => Kind == ApplicationRuleKind.CustomRule ? "编辑" : "重选";

    public string IconText => Kind switch
    {
        ApplicationRuleKind.ExecutablePath => string.Empty,
        ApplicationRuleKind.DirectoryPath => "D",
        _ => "*"
    };

    public string SearchText => $"{Name} {Value} {Detail}";

    public static ConfiguredApplication CreateExecutable(string filePath, ImageSource? icon)
    {
        return new ConfiguredApplication(
            System.IO.Path.GetFileName(filePath),
            filePath,
            filePath,
            ApplicationRuleKind.ExecutablePath,
            icon);
    }

    public static ConfiguredApplication CreateDirectory(string directoryPath)
    {
        var normalized = ProcessMatcher.TryNormalizeDirectoryPattern(directoryPath, out var normalizedDirectory)
            ? normalizedDirectory
            : directoryPath;
        var trimmed = Path.TrimEndingDirectorySeparator(normalized);
        var name = Path.GetFileName(trimmed);
        if (string.IsNullOrWhiteSpace(name))
        {
            name = normalized;
        }

        return new ConfiguredApplication(
            name,
            normalized,
            normalized,
            ApplicationRuleKind.DirectoryPath,
            null);
    }

    public static ConfiguredApplication CreateRule(string rule)
    {
        return new ConfiguredApplication(
            rule,
            rule,
            "自定义 apps 规则",
            ApplicationRuleKind.CustomRule,
            null);
    }
}
