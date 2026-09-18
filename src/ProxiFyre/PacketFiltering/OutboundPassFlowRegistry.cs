namespace ProxiFyre;

internal sealed class OutboundPassFlowRegistry(int maxFlows, TimeSpan ttl)
{
    private readonly Dictionary<RelayOutboundFlow, DateTimeOffset> _flows = [];

    public int Count => _flows.Count;

    public bool Contains(RelayOutboundFlow flow)
    {
        return _flows.ContainsKey(flow);
    }

    public bool Register(RelayOutboundFlow flow, DateTimeOffset now)
    {
        var evicted = false;
        if (!_flows.ContainsKey(flow) && _flows.Count >= maxFlows)
        {
            var oldest = _flows.MinBy(static pair => pair.Value);
            _flows.Remove(oldest.Key);
            evicted = true;
        }

        _flows[flow] = now;
        return evicted;
    }

    public bool TryAdd(RelayOutboundFlow flow, DateTimeOffset now)
    {
        if (_flows.ContainsKey(flow))
        {
            _flows[flow] = now;
            return true;
        }

        if (_flows.Count >= maxFlows)
        {
            return false;
        }

        _flows[flow] = now;
        return true;
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

    public bool Remove(RelayOutboundFlow flow)
    {
        return _flows.Remove(flow);
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
