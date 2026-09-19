using Microsoft.Win32.SafeHandles;

namespace ProxiFyre;

internal sealed class AdapterPipelineSet
{
    private readonly IntPtr _driverHandle;
    private readonly Action<string> _log;
    private AdapterPipeline[] _pipelines = [];
    private IntPtr[] _handles = [];
    private bool _useWfpClassifier;
    private int _nextReadIndex;

    public AdapterPipelineSet(IntPtr driverHandle, Action<string> log)
    {
        _driverHandle = driverHandle;
        _log = log;
    }

    public IReadOnlyList<AdapterPipeline> Pipelines => _pipelines;

    public IReadOnlyCollection<IntPtr> Handles => _handles;

    public int Count => _pipelines.Length;

    public IEnumerable<string> Names => _pipelines.Select(pipeline => pipeline.Name);

    public void Configure(bool useWfpClassifier)
    {
        _useWfpClassifier = useWfpClassifier;

        var adapterList = new NdisApi.TcpAdapterList();
        if (!NdisApi.GetTcpipBoundAdaptersInfo(_driverHandle, ref adapterList))
        {
            throw new InvalidOperationException("Failed to enumerate TCP/IP bound adapters.");
        }

        var pipelines = new List<AdapterPipeline>(checked((int)adapterList.Count));
        for (var i = 0; i < adapterList.Count; i++)
        {
            var adapter = adapterList.GetHandle(i);
            if (adapter == IntPtr.Zero)
            {
                continue;
            }

            var name = adapterList.GetName(i);
            var mtu = adapterList.GetMtu(i) is > 0 and <= ushort.MaxValue
                ? (int)adapterList.GetMtu(i)
                : 1500;
            var interfaceIndex = ResolveInterfaceIndex(name, adapterList.GetMacAddress(i));
            if (interfaceIndex <= 0 && useWfpClassifier)
            {
                _log(
                    $"Could not resolve the Windows interface index for WinpkFilter adapter '{name}'; WFP flows on this adapter will pass through.");
            }

            var mode = new NdisApi.AdapterMode
            {
                AdapterHandle = adapter,
                // Direct relay only needs app-originated packets. Keeping receive
                // traffic on the normal stack preserves Windows attribution.
                Flags = useWfpClassifier ? 0 : NdisApi.MstcpFlagSentTunnel
            };

            if (!NdisApi.SetAdapterMode(_driverHandle, ref mode))
            {
                _log($"Failed to set send tunnel mode for adapter handle 0x{adapter.ToInt64():X}.");
            }

            pipelines.Add(new AdapterPipeline(_driverHandle, adapter, name, mtu, interfaceIndex));
        }

        if (pipelines.Count == 0)
        {
            throw new InvalidOperationException("No TCP/IP adapters were returned by WinpkFilter.");
        }

        _pipelines = pipelines.ToArray();
        _handles = pipelines.Select(pipeline => pipeline.Handle).ToArray();
        _nextReadIndex = 0;
        _log(
            $"Filtering {_pipelines.Length} adapter(s) on send path using {(useWfpClassifier ? "WFP target-only mode" : "userspace send-tunnel fallback without kernel pass cache")}: {string.Join(", ", Names)}");
    }

    public void BindPacketEvent(SafeWaitHandle packetEvent)
    {
        foreach (var pipeline in _pipelines)
        {
            NdisApi.SetPacketEvent(_driverHandle, pipeline.Handle, packetEvent);
        }
    }

    public bool TryReadAndProcess(IAdapterPacketProcessor processor)
    {
        var pipelines = _pipelines;
        var adapterCount = pipelines.Length;
        if (adapterCount == 0)
        {
            return false;
        }

        var startIndex = _nextReadIndex % adapterCount;
        for (var offset = 0; offset < adapterCount; offset++)
        {
            var adapterIndex = (startIndex + offset) % adapterCount;
            if (!pipelines[adapterIndex].TryReadAndProcess(processor))
            {
                continue;
            }

            _nextReadIndex = (adapterIndex + 1) % adapterCount;
            return true;
        }

        _nextReadIndex = (startIndex + 1) % adapterCount;
        return false;
    }

    public bool RebindIfChanged(SafeWaitHandle packetEvent)
    {
        var adapterList = new NdisApi.TcpAdapterList();
        if (!NdisApi.GetTcpipBoundAdaptersInfo(_driverHandle, ref adapterList))
        {
            return false;
        }

        var currentAdapters = new HashSet<IntPtr>();
        for (var i = 0; i < adapterList.Count; i++)
        {
            var adapter = adapterList.GetHandle(i);
            if (adapter != IntPtr.Zero)
            {
                currentAdapters.Add(adapter);
            }
        }

        if (currentAdapters.SetEquals(_handles))
        {
            return false;
        }

        _log(
            $"WinpkFilter adapter set changed; rebinding {currentAdapters.Count} adapter(s) before continuing.");
        Restore();
        Configure(_useWfpClassifier);
        BindPacketEvent(packetEvent);
        return true;
    }

    public bool TryResolveHandle(int interfaceIndex, out IntPtr adapterHandle)
    {
        foreach (var pipeline in _pipelines)
        {
            if (pipeline.InterfaceIndex == interfaceIndex)
            {
                adapterHandle = pipeline.Handle;
                return true;
            }
        }

        adapterHandle = IntPtr.Zero;
        return false;
    }

    public bool TryGetInterfaceIndex(IntPtr adapterHandle, out int interfaceIndex)
    {
        foreach (var pipeline in _pipelines)
        {
            if (pipeline.Handle == adapterHandle)
            {
                interfaceIndex = pipeline.InterfaceIndex;
                return true;
            }
        }

        interfaceIndex = 0;
        return false;
    }

    public bool TryGetMtu(IntPtr adapterHandle, out int mtu)
    {
        foreach (var pipeline in _pipelines)
        {
            if (pipeline.Handle == adapterHandle)
            {
                mtu = pipeline.Mtu;
                return true;
            }
        }

        mtu = 1500;
        return false;
    }

    public void Restore()
    {
        var adapters = new HashSet<IntPtr>(_handles);
        var adapterList = new NdisApi.TcpAdapterList();
        if (NdisApi.GetTcpipBoundAdaptersInfo(_driverHandle, ref adapterList))
        {
            for (var i = 0; i < adapterList.Count; i++)
            {
                var adapter = adapterList.GetHandle(i);
                if (adapter != IntPtr.Zero)
                {
                    adapters.Add(adapter);
                }
            }
        }

        NdisApi.ResetPacketFilterTable(_driverHandle);
        foreach (var adapter in adapters)
        {
            if (!NdisApi.SetPacketEvent(_driverHandle, adapter, IntPtr.Zero))
            {
                _log($"Failed to clear packet event for adapter handle 0x{adapter.ToInt64():X}.");
            }

            var mode = new NdisApi.AdapterMode { AdapterHandle = adapter, Flags = 0 };
            if (!NdisApi.SetAdapterMode(_driverHandle, ref mode))
            {
                _log($"Failed to restore normal mode for adapter handle 0x{adapter.ToInt64():X}.");
            }

            if (!NdisApi.FlushAdapterPacketQueue(_driverHandle, adapter))
            {
                _log($"Failed to flush adapter queue for adapter handle 0x{adapter.ToInt64():X}.");
            }
        }
    }

    private static int ResolveInterfaceIndex(string adapterName, byte[] macAddress)
    {
        return NetworkInterfaceIndexResolver.FindAdapterIndex(adapterName, macAddress);
    }
}
