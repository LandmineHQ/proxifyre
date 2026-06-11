using System.Net;

namespace TrafficTest;

internal sealed record StunScanResult(string Target, bool Success, double AverageMs, IPEndPoint? MappedEndPoint, string? Error);
