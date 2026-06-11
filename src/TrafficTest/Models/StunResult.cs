using System.Net;

namespace TrafficTest;

internal sealed record StunResult(bool Success, IPEndPoint? MappedEndPoint, IPEndPoint? RemoteEndPoint, int ResponseBytes, string? Error)
{
    public static StunResult Ok(IPEndPoint? mappedEndPoint, IPEndPoint remoteEndPoint, int responseBytes)
    {
        return new StunResult(true, mappedEndPoint, remoteEndPoint, responseBytes, null);
    }

    public static StunResult Fail(string? error)
    {
        return new StunResult(false, null, null, 0, error);
    }
}
