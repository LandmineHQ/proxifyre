namespace TrafficTest;

internal static class CliOptions
{
    public static bool TryReadValue(string[] args, ref int index, string optionName, out string value)
    {
        value = string.Empty;
        var arg = args[index];
        if (arg.Equals(optionName, StringComparison.OrdinalIgnoreCase))
        {
            if (index + 1 >= args.Length)
            {
                throw new ArgumentException($"{optionName} requires a value.");
            }

            value = args[++index];
            return true;
        }

        var prefix = optionName + "=";
        if (arg.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            value = arg[prefix.Length..];
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException($"{optionName} requires a value.");
            }

            return true;
        }

        return false;
    }

    public static int ParsePositiveInt(string optionName, string value)
    {
        if (!int.TryParse(value, out var parsed) || parsed <= 0)
        {
            throw new ArgumentException($"{optionName} requires a positive integer.");
        }

        return parsed;
    }

    public static int ParseNonNegativeInt(string optionName, string value)
    {
        if (!int.TryParse(value, out var parsed) || parsed < 0)
        {
            throw new ArgumentException($"{optionName} requires a non-negative integer.");
        }

        return parsed;
    }
}
