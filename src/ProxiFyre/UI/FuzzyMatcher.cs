using System.Globalization;
using System.Text;

namespace ProxiFyre;

internal static class FuzzyMatcher
{
    public static bool IsMatch(string? query, string text)
    {
        var normalizedQuery = Normalize(query);
        if (normalizedQuery.Length == 0)
        {
            return true;
        }

        var normalizedText = Normalize(text);
        if (normalizedText.Contains(normalizedQuery, StringComparison.Ordinal))
        {
            return true;
        }

        var queryIndex = 0;
        foreach (var character in normalizedText)
        {
            if (character != normalizedQuery[queryIndex])
            {
                continue;
            }

            queryIndex++;
            if (queryIndex == normalizedQuery.Length)
            {
                return true;
            }
        }

        return false;
    }

    private static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(value.Length);
        foreach (var character in value.Normalize(NormalizationForm.FormKC))
        {
            if (character is '-' or '_' or ' ' || char.IsWhiteSpace(character))
            {
                continue;
            }

            builder.Append(char.ToLower(character, CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }
}
