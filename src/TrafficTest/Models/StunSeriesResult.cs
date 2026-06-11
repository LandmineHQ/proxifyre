using System.Globalization;

namespace TrafficTest;

internal sealed record StunSeriesResult(
    string Label,
    int SuccessCount,
    int FailureCount,
    double MinMs,
    double AverageMs,
    double P95Ms,
    double MaxMs)
{
    public bool HasSamples => SuccessCount > 0;

    public bool Success => HasSamples && FailureCount == 0;

    public static StunSeriesResult Create(string label, IReadOnlyList<double> samples, int failures)
    {
        if (samples.Count == 0)
        {
            return new StunSeriesResult(label, 0, failures, double.NaN, double.NaN, double.NaN, double.NaN);
        }

        var ordered = samples.Order().ToArray();
        var p95Index = Math.Min(ordered.Length - 1, (int)Math.Ceiling(ordered.Length * 0.95) - 1);
        return new StunSeriesResult(
            label,
            samples.Count,
            failures,
            ordered[0],
            samples.Average(),
            ordered[p95Index],
            ordered[^1]);
    }

    public override string ToString()
    {
        return $"ok={SuccessCount} fail={FailureCount} min={MinMs:F2} ms avg={AverageMs:F2} ms p95={P95Ms:F2} ms max={MaxMs:F2} ms";
    }

    public string ToMachineLine()
    {
        return string.Create(
            CultureInfo.InvariantCulture,
            $"STUN_SERIES_RESULT ok={SuccessCount} fail={FailureCount} min={MinMs:F6} avg={AverageMs:F6} p95={P95Ms:F6} max={MaxMs:F6}");
    }

    public static bool TryParseMachineLine(string label, string line, out StunSeriesResult result)
    {
        result = Create(label, [], 1);
        const string prefix = "STUN_SERIES_RESULT ";
        if (!line.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in line[prefix.Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = part.IndexOf('=');
            if (separator <= 0 || separator == part.Length - 1)
            {
                continue;
            }

            values[part[..separator]] = part[(separator + 1)..];
        }

        if (!TryGetInt(values, "ok", out var ok)
            || !TryGetInt(values, "fail", out var fail)
            || !TryGetDouble(values, "min", out var min)
            || !TryGetDouble(values, "avg", out var avg)
            || !TryGetDouble(values, "p95", out var p95)
            || !TryGetDouble(values, "max", out var max))
        {
            return false;
        }

        result = new StunSeriesResult(label, ok, fail, min, avg, p95, max);
        return true;
    }

    private static bool TryGetInt(Dictionary<string, string> values, string key, out int value)
    {
        value = 0;
        return values.TryGetValue(key, out var raw)
            && int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryGetDouble(Dictionary<string, string> values, string key, out double value)
    {
        value = double.NaN;
        return values.TryGetValue(key, out var raw)
            && double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out value);
    }
}
