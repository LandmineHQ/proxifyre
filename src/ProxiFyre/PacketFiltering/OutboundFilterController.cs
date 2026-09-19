using System.Collections.Concurrent;

namespace ProxiFyre;

internal sealed class OutboundFilterController
{
    private const int MaxTemporaryPassFlows = 1024;
    private const int MaxTargetRedirectFlows = 12288;
    private static readonly TimeSpan TemporaryPassFlowTtl = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan OutboundFilterApplyInterval = TimeSpan.FromMilliseconds(50);
    private static readonly TimeSpan TemporaryPassCleanupInterval = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan OutboundFilterRetryInterval = TimeSpan.FromSeconds(1);

    private readonly Func<IntPtr> _getDriverHandle;
    private readonly Func<AdapterPipelineSet?> _getAdapters;
    private readonly Func<long> _getConfigurationGeneration;
    private readonly PacketWakeSignal _wakeSignal;
    private readonly Action<string, string, TimeSpan> _logDetail;
    private readonly Action<string, string, TimeSpan> _logThrottled;
    private readonly TimeProvider _timeProvider;
    private readonly object _sync = new();
    private readonly Dictionary<RelayOutboundFlow, int> _outboundBypassFlows = [];
    private readonly OutboundPassFlowRegistry _targetRedirectFlows =
        new(MaxTargetRedirectFlows, TimeSpan.FromMinutes(10));
    private readonly ConcurrentDictionary<RelayOutboundFlow, ProcessInfo> _wfpProcessByFlow = new();
    private readonly ConcurrentDictionary<RelayOutboundFlow, DateTimeOffset> _wfpPendingRedirects = new();
    private readonly HashSet<RelayOutboundFlow> _wfpActiveRedirects = [];
    private readonly OutboundPassFlowRegistry _temporaryPassFlows =
        new(MaxTemporaryPassFlows, TemporaryPassFlowTtl);
    private bool _dirty;
    private bool _forceApply;
    private DateTimeOffset _lastApply;
    private DateTimeOffset _nextRetry;
    private DateTimeOffset _nextTemporaryPassCleanup;
    private long _lastConfigurationGeneration;
    private long _filterApplyFailures;

    public OutboundFilterController(
        Func<IntPtr> getDriverHandle,
        Func<AdapterPipelineSet?> getAdapters,
        Func<long> getConfigurationGeneration,
        PacketWakeSignal wakeSignal,
        Action<string, string, TimeSpan> logDetail,
        Action<string, string, TimeSpan> logThrottled,
        TimeProvider timeProvider)
    {
        _getDriverHandle = getDriverHandle;
        _getAdapters = getAdapters;
        _getConfigurationGeneration = getConfigurationGeneration;
        _wakeSignal = wakeSignal;
        _logDetail = logDetail;
        _logThrottled = logThrottled;
        _timeProvider = timeProvider;
    }

    public bool UseWfpClassifier { get; private set; }

    public bool FragmentCacheEnabled { get; private set; }

    public long FilterApplyFailures => Interlocked.Read(ref _filterApplyFailures);

    public int KernelPassFlowCount
    {
        get
        {
            lock (_sync)
            {
                return _outboundBypassFlows.Count + _temporaryPassFlows.Count;
            }
        }
    }

    public bool Initialize(bool requestWfpClassifier)
    {
        var handle = _getDriverHandle();
        UseWfpClassifier = requestWfpClassifier;
        lock (_sync)
        {
            _dirty = true;
            _forceApply = true;
        }

        if (UseWfpClassifier)
        {
            FragmentCacheEnabled = NdisApi.SetPacketFragmentCacheState(handle, enabled: true);
            return FragmentCacheEnabled;
        }

        FragmentCacheEnabled = false;
        NdisApi.SetPacketFragmentCacheState(handle, enabled: false);
        return true;
    }

    public void DisableWfpFallback()
    {
        UseWfpClassifier = false;
        FragmentCacheEnabled = false;
        NdisApi.SetPacketFragmentCacheState(_getDriverHandle(), enabled: false);
        MarkDirty(force: true);
    }

    public void RegisterOutboundBypass(RelayOutboundFlow flow)
    {
        lock (_sync)
        {
            _outboundBypassFlows.TryGetValue(flow, out var count);
            _outboundBypassFlows[flow] = count + 1;
            if (UseWfpClassifier || FragmentCacheEnabled)
            {
                _dirty = true;
            }
        }

        _wakeSignal.Pulse();
        _logDetail(
            $"Registered relay outbound kernel pass flow: {flow}",
            $"relay-pass-register:{flow}",
            TimeSpan.FromSeconds(2));
    }

    public void UnregisterOutboundBypass(RelayOutboundFlow flow)
    {
        var changed = false;
        lock (_sync)
        {
            if (!_outboundBypassFlows.TryGetValue(flow, out var count))
            {
                return;
            }

            if (count <= 1)
            {
                _outboundBypassFlows.Remove(flow);
            }
            else
            {
                _outboundBypassFlows[flow] = count - 1;
            }

            changed = UseWfpClassifier || FragmentCacheEnabled;
            if (changed)
            {
                _dirty = true;
                _forceApply = true;
            }
        }

        if (!changed)
        {
            return;
        }

        _wakeSignal.Pulse();
        _logDetail(
            $"Unregistered relay outbound kernel pass flow: {flow}",
            $"relay-pass-unregister:{flow}",
            TimeSpan.FromSeconds(2));
    }

    public bool RegisterTargetRedirect(
        RelayOutboundFlow flow,
        ProcessInfo process,
        DateTimeOffset pendingDeadline)
    {
        if (!UseWfpClassifier || flow.AdapterHandle == IntPtr.Zero || flow.Dot1q != 0)
        {
            return false;
        }

        lock (_sync)
        {
            var existed = _targetRedirectFlows.Contains(flow);
            if (!_targetRedirectFlows.TryAdd(flow, _timeProvider.GetUtcNow()))
            {
                _logThrottled(
                    $"WFP target redirect flow limit reached ({MaxTargetRedirectFlows}); passing new target flow directly.",
                    "wfp-target-limit",
                    TimeSpan.FromSeconds(5));
                return false;
            }

            _wfpProcessByFlow[flow] = process;
            if (!_wfpActiveRedirects.Contains(flow))
            {
                _wfpPendingRedirects[flow] = pendingDeadline;
            }

            if (existed)
            {
                return true;
            }

            if (!ApplyTargetRedirectFilters())
            {
                RemoveTargetRedirectLocked(flow);
                return false;
            }
        }

        _logDetail(
            $"Registered WFP target redirect flow: {flow}",
            $"wfp-target-register:{flow}",
            TimeSpan.FromSeconds(2));
        return true;
    }

    public void UnregisterTargetRedirect(RelayOutboundFlow flow)
    {
        var removed = false;
        lock (_sync)
        {
            removed = RemoveTargetRedirectLocked(flow);
        }

        if (removed)
        {
            _wakeSignal.Pulse();
        }
    }

    public void RefreshTargetRedirect(RelayOutboundFlow flow)
    {
        lock (_sync)
        {
            if (_targetRedirectFlows.Count == 0)
            {
                return;
            }

            _ = _targetRedirectFlows.TryAdd(flow, _timeProvider.GetUtcNow());
        }
    }

    public void MarkTargetRedirectActive(RelayOutboundFlow flow)
    {
        lock (_sync)
        {
            _wfpPendingRedirects.TryRemove(flow, out _);
            if (_targetRedirectFlows.Contains(flow))
            {
                _wfpActiveRedirects.Add(flow);
            }
            else
            {
                _wfpActiveRedirects.Remove(flow);
            }
        }
    }

    public bool TryGetWfpProcess(RelayOutboundFlow flow, out ProcessInfo process)
    {
        return _wfpProcessByFlow.TryGetValue(flow, out process!);
    }

    public void RegisterTemporaryPassFlow(
        PacketView packet,
        IntPtr adapterHandle,
        uint dot1q,
        bool allowPassFilter = true)
    {
        // UDP can begin fragmenting after any datagram, so a transport-only kernel
        // PASS rule cannot safely preserve fragment ordering without WFP metadata.
        if (!allowPassFilter
            || UseWfpClassifier
            || !packet.IsTcp
            || !FragmentCacheEnabled
            || dot1q != 0
            || packet.IsLinkLayerBroadcastOrMulticast())
        {
            return;
        }

        var flow = new RelayOutboundFlow(
            adapterHandle,
            PacketView.ProtocolTcp,
            packet.SourceAddress,
            packet.DestinationAddress,
            packet.SourcePort,
            packet.DestinationPort,
            dot1q);
        var now = _timeProvider.GetUtcNow();
        lock (_sync)
        {
            if (_temporaryPassFlows.Register(flow, now))
            {
                _forceApply = true;
            }

            _dirty = true;
        }

        _logDetail(
            $"Temporary kernel pass flow registered: {flow}",
            $"temporary-pass-register:{flow}",
            TimeSpan.FromSeconds(5));
    }

    public void RemoveTemporaryPassFlow(PacketView packet, IntPtr adapterHandle, uint dot1q)
    {
        var flow = new RelayOutboundFlow(
            adapterHandle,
            PacketView.ProtocolTcp,
            packet.SourceAddress,
            packet.DestinationAddress,
            packet.SourcePort,
            packet.DestinationPort,
            dot1q);
        var removed = false;
        lock (_sync)
        {
            if (_temporaryPassFlows.Remove(flow))
            {
                _dirty = true;
                _forceApply = true;
                removed = true;
            }
        }

        if (removed)
        {
            _logDetail(
                $"Temporary kernel pass flow revoked: {flow}",
                $"temporary-pass-revoke:{flow}",
                TimeSpan.FromSeconds(5));
        }
    }

    public void Maintain()
    {
        var handle = _getDriverHandle();
        if (handle == IntPtr.Zero)
        {
            return;
        }

        if (!UseWfpClassifier && !FragmentCacheEnabled)
        {
            lock (_sync)
            {
                if (_lastConfigurationGeneration != _getConfigurationGeneration())
                {
                    _lastConfigurationGeneration = _getConfigurationGeneration();
                    _temporaryPassFlows.Clear();
                }
            }

            return;
        }

        lock (_sync)
        {
            var now = _timeProvider.GetUtcNow();
            if (_lastConfigurationGeneration != _getConfigurationGeneration())
            {
                _lastConfigurationGeneration = _getConfigurationGeneration();
                _temporaryPassFlows.Clear();
                _dirty = true;
                _forceApply = true;
            }

            if (_nextTemporaryPassCleanup == default || now >= _nextTemporaryPassCleanup)
            {
                _nextTemporaryPassCleanup = now + TemporaryPassCleanupInterval;
                if (_temporaryPassFlows.RemoveExpired(now))
                {
                    _dirty = true;
                    _forceApply = true;
                }
            }

            if (ExpirePendingWfpRedirects(now))
            {
                _dirty = true;
                _forceApply = true;
            }

            if (!_dirty
                || (!_forceApply
                    && ((_nextRetry != default && now < _nextRetry)
                        || (_lastApply != default
                            && now - _lastApply < OutboundFilterApplyInterval))))
            {
                return;
            }

            _forceApply = false;
            _ = ApplyOutboundFilters();
        }
    }

    public void MarkDirty(bool force)
    {
        lock (_sync)
        {
            _dirty = true;
            _forceApply |= force;
        }

        _wakeSignal.Pulse();
    }

    public void Reset()
    {
        lock (_sync)
        {
            _outboundBypassFlows.Clear();
            _targetRedirectFlows.Clear();
            _wfpProcessByFlow.Clear();
            _wfpPendingRedirects.Clear();
            _wfpActiveRedirects.Clear();
            _temporaryPassFlows.Clear();
            _dirty = true;
            _forceApply = true;
        }
    }

    private bool ApplyOutboundFilters()
    {
        if (_getDriverHandle() == IntPtr.Zero)
        {
            return false;
        }

        return UseWfpClassifier
            ? ApplyTargetRedirectFilters()
            : ApplyUserspacePassFilters();
    }

    private bool ApplyTargetRedirectFilters()
    {
        if (!FragmentCacheEnabled)
        {
            return false;
        }

        var filters = new List<NdisApi.StaticFilter>(_targetRedirectFlows.Count);
        foreach (var flow in _targetRedirectFlows.Snapshot())
        {
            if (flow.AdapterHandle == IntPtr.Zero || flow.Dot1q != 0)
            {
                continue;
            }

            filters.Add(NdisApi.CreateOutboundRedirectFilter(
                flow.AdapterHandle,
                flow.Protocol,
                flow.LocalAddress,
                flow.RemoteAddress,
                flow.LocalPort,
                flow.RemotePort));
        }

        if (!NdisApi.SetPacketFilterTable(_getDriverHandle(), filters))
        {
            Interlocked.Increment(ref _filterApplyFailures);
            _logThrottled(
                $"SetPacketFilterTable failed for target redirect flows count={filters.Count} win32={NdisApi.LastWin32Error}",
                "set-target-filter-failed",
                TimeSpan.FromSeconds(2));
            return false;
        }

        _dirty = false;
        _forceApply = false;
        _lastApply = _timeProvider.GetUtcNow();
        _nextRetry = default;
        return true;
    }

    private bool ApplyUserspacePassFilters()
    {
        var handle = _getDriverHandle();
        if (handle == IntPtr.Zero)
        {
            return false;
        }

        if (!FragmentCacheEnabled)
        {
            if (NdisApi.ResetPacketFilterTable(handle))
            {
                _dirty = false;
                _forceApply = false;
                _lastApply = _timeProvider.GetUtcNow();
                _nextRetry = default;
            }
            else
            {
                _forceApply = false;
                _lastApply = _timeProvider.GetUtcNow();
                _nextRetry = _lastApply + OutboundFilterRetryInterval;
            }

            return false;
        }

        var adapters = _getAdapters()?.Handles ?? Array.Empty<IntPtr>();
        var passFlows = new HashSet<RelayOutboundFlow>(_outboundBypassFlows.Keys);
        passFlows.UnionWith(_temporaryPassFlows.Snapshot());
        var filters = new List<NdisApi.StaticFilter>(
            passFlows.Count * Math.Max(adapters.Count, 1));
        foreach (var flow in passFlows)
        {
            if (flow.Dot1q != 0)
            {
                continue;
            }

            var flowAdapters = flow.AdapterHandle != IntPtr.Zero
                ? [flow.AdapterHandle]
                : adapters;
            foreach (var adapter in flowAdapters)
            {
                filters.Add(NdisApi.CreateOutboundPassFilter(
                    adapter,
                    flow.Protocol,
                    flow.LocalAddress,
                    flow.RemoteAddress,
                    flow.LocalPort,
                    flow.RemotePort));
            }
        }

        if (!NdisApi.SetPacketFilterTable(handle, filters))
        {
            Interlocked.Increment(ref _filterApplyFailures);
            _logThrottled(
                $"SetPacketFilterTable failed for relay outbound pass flows count={filters.Count} win32={NdisApi.LastWin32Error}",
                "set-static-filter-failed",
                TimeSpan.FromSeconds(2));
            if (NdisApi.ResetPacketFilterTable(handle))
            {
                _logThrottled(
                    "Kernel pass table reset after update failure; dynamic pass filtering is disabled.",
                    "kernel-pass-disabled",
                    TimeSpan.FromSeconds(5));
                FragmentCacheEnabled = false;
                _dirty = false;
                _forceApply = false;
                _nextRetry = default;
                return false;
            }

            _dirty = true;
            _lastApply = _timeProvider.GetUtcNow();
            _nextRetry = _lastApply + OutboundFilterRetryInterval;
            return false;
        }

        _dirty = false;
        _lastApply = _timeProvider.GetUtcNow();
        _nextRetry = default;
        return true;
    }

    private bool RemoveTargetRedirectLocked(RelayOutboundFlow flow)
    {
        if (!_targetRedirectFlows.Remove(flow))
        {
            return false;
        }

        _wfpProcessByFlow.TryRemove(flow, out _);
        _wfpPendingRedirects.TryRemove(flow, out _);
        _wfpActiveRedirects.Remove(flow);
        return true;
    }

    private bool ExpirePendingWfpRedirects(DateTimeOffset now)
    {
        var changed = false;
        foreach (var pair in _wfpPendingRedirects)
        {
            if (now < pair.Value)
            {
                continue;
            }

            if (RemoveTargetRedirectLocked(pair.Key))
            {
                changed = true;
                _logDetail(
                    $"WFP target redirect expired before first packet: {pair.Key}",
                    $"wfp-target-orphan:{pair.Key}",
                    TimeSpan.FromSeconds(5));
            }
        }

        return changed;
    }
}
