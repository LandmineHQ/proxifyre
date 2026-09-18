namespace ProxiFyre;

internal sealed class OutboundPassFlowRegistry(int maxFlows, TimeSpan ttl)
{
    private readonly Dictionary<RelayOutboundFlow, DateTimeOffset> _flows = [];

    public int Count => _flows.Count;

    public void Register(RelayOutboundFlow flow, DateTimeOffset now)
    {
        if (!_flows.ContainsKey(flow) && _flows.Count >= maxFlows)
        {
            var oldest = _flows.MinBy(static pair => pair.Value);
            _flows.Remove(oldest.Key);
        }

        _flows[flow] = now;
    }

    public bool RemoveExpired(DateTimeOffset now)
    {
        var changed = false;
        foreach (var pair in _flows.ToArray())
        {
            if (now - pair.Value <= ttl)
            {
                continue;
            }

            _flows.Remove(pair.Key);
            changed = true;
        }

        return changed;
    }

    public RelayOutboundFlow[] Snapshot()
    {
        return _flows.Keys.ToArray();
    }

    public void Clear()
    {
        _flows.Clear();
    }
}
